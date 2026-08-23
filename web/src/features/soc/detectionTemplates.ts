/**
 * Starting points for writing a detection.
 *
 * # Why these exist
 *
 * The push form used to be an empty textarea labelled "TracingPolicy YAML".
 * That assumes the operator already knows Tetragon's dialect — the apiVersion,
 * that a kprobe needs `call` plus typed `args` plus `selectors`, that a file
 * watch hooks `security_file_permission` rather than `open`, that the argument
 * mask values are MAY_READ/MAY_WRITE bit flags. A Safaricom engineer has no
 * reason to know any of that, and a blank box gives them nowhere to begin.
 *
 * Every template below is a COMPLETE, VALID policy that loads as-is. That is
 * deliberate: the first thing an engineer should be able to do is push one
 * unchanged, watch it appear in the kernel and start producing events, and only
 * then edit it. Learning by diff from something that works beats learning by
 * debugging something that does not.
 *
 * Each is lifted from a policy running in production on this estate — the file
 * watch from sensitive-files.yaml, the network watch from network-watch.yaml,
 * the syscall watch from privilege-escalation.yaml — so the dialect is proven
 * rather than reconstructed from documentation.
 *
 * # Every template is monitor mode
 *
 * `policy-mode: monitor` is declarative and survives a restart, and it
 * suppresses every enforcing action in the kernel. An enforcing TracingPolicy
 * kills with no audit row, no reversal and no kill-switch (threat-model EN-3),
 * so it is not something to arrive at by editing a template.
 */
export interface DetectionTemplate {
  id: string;
  title: string;
  /** The question an operator is actually trying to answer. */
  intent: string;
  /** What to change, in the order they should change it. */
  editThese: string[];
  name: string;
  yaml: string;
}

const MODE_BLOCK = `  # monitor = record only. It is declarative, so it survives a restart, and it
  # suppresses every enforcing action in the kernel. Leave this alone: an
  # enforcing policy kills with no audit row and no kill-switch.
  options:
    - name: "policy-mode"
      value: "monitor"`;

export const DETECTION_TEMPLATES: DetectionTemplate[] = [
  {
    id: "file-access",
    title: "Watch a file or directory",
    intent: "Tell me when anything reads or writes a path I care about — a credential store, a config file, a key directory.",
    editThese: [
      "metadata.name — a short unique name; it is how you remove it later",
      "the values under Prefix — the paths to watch (a trailing / matches everything beneath it)",
      "leave the Mask values alone unless you only want reads (4) or only writes (2)"
    ],
    name: "watch-my-paths",
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  # CHANGE ME — must be unique, and must match the Policy name field above.
  name: "watch-my-paths"
spec:
${MODE_BLOCK}
  kprobes:
    # security_file_permission is the LSM hook, not open(). Hooking here means
    # the watch cannot be bypassed by using a different syscall to reach the
    # same file.
    - call: "security_file_permission"
      syscall: false
      return: true
      args:
        - index: 0
          type: "file"
        - index: 1
          type: "int"
      returnArg:
        index: 0
        type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                # CHANGE ME — the paths to watch. A trailing slash matches the
                # whole directory tree beneath it.
                - "/etc/my-app/secrets"
                - "/opt/billing/keys/"
            - index: 1
              operator: "Mask"
              values:
                - "2"   # MAY_WRITE
                - "4"   # MAY_READ
          matchActions:
            - action: Post
`
  },
  {
    id: "outbound",
    title: "Watch a program making network connections",
    intent: "Tell me when a specific binary dials out — a shell, an interpreter, a tool that has no business talking to the network.",
    editThese: [
      "metadata.name",
      "the values under matchBinaries — the full paths of the programs to watch",
      "nothing else; tcp_connect and the sock arg are what make this work"
    ],
    name: "watch-my-egress",
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  # CHANGE ME
  name: "watch-my-egress"
spec:
${MODE_BLOCK}
  kprobes:
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
      selectors:
        - matchBinaries:
            - operator: "In"
              values:
                # CHANGE ME — FULL paths, and list every location the binary can
                # live in. Matching is exact: /bin/bash and /usr/bin/bash are
                # different strings even when they are the same file.
                - "/usr/bin/python3"
                - "/usr/bin/perl"
          matchActions:
            - action: Post
`
  },
  {
    id: "syscall",
    title: "Watch a syscall with a specific argument",
    intent: "Tell me when something calls a syscall in a way that matters — setuid(0), a specific mount, a particular ioctl.",
    editThese: [
      "metadata.name",
      "the call — the syscall symbol, prefixed __x64_sys_ on x86-64",
      "the operator and values under matchArgs — which argument value you care about"
    ],
    name: "watch-my-syscall",
    yaml: `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  # CHANGE ME
  name: "watch-my-syscall"
spec:
${MODE_BLOCK}
  kprobes:
    # CHANGE ME — the syscall symbol. On x86-64 these carry an __x64_sys_
    # prefix. If the symbol does not exist on the host's kernel, Tetragon
    # rejects the policy and the push reports the daemon's own error.
    - call: "__x64_sys_setuid"
      syscall: true
      args:
        - index: 0
          type: "int"
      selectors:
        - matchArgs:
            # CHANGE ME — which argument value is worth an event. Filtering in
            # the kernel matters: without it every uid change on the box is an
            # event, and the noise buries the finding.
            - index: 0
              operator: "Equal"
              values:
                - "0"
          matchActions:
            - action: Post
`
  }
];
