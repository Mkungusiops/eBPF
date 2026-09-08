#!/usr/bin/env bash
#
# scripts/deploy/estate.sh — deploy the whole production estate, in order.
#
#   ./scripts/deploy/estate.sh                 # everything, with a confirm gate
#   ./scripts/deploy/estate.sh --only agents   # cp | engine | agents | verify
#   ./scripts/deploy/estate.sh --skip-build    # reuse the current build
#   ASSUME_YES=1 ./scripts/deploy/estate.sh    # unattended
#   ASSISTANT_OFF=1 ./scripts/deploy/estate.sh # deliberately REMOVE the assistant
#
# Why this exists: the estate needs six commands in a specific order, each
# carrying environment variables that are NOT optional and whose omission fails
# silently. Every one of those omissions has already happened here and each cost
# an outage or a false result:
#
#   TLS=1 + a DNS hostname  the provisioner rewrites the nginx site on EVERY run
#                           and binds server_name to TARGET_HOST, emitting :443
#                           only when TLS is requested. Deploying with an IP
#                           replaced the TLS vhost with a plaintext one and took
#                           console.adanianlabs.io fully offline — while every
#                           systemd unit reported active and curl http://<ip>/
#                           returned 200, so every health check passed through
#                           the outage.
#   DATA_MODE=none          defaults to `sim`, and is needed in TWO places:
#                           - control plane: a plain redeploy resurrects the
#                             sim-agents beside the real ones, and a sim acks
#                             STATUS_APPLIED for a process it never touched,
#                             which is the false-containment condition.
#                           - each AGENT: the provisioner installs a synthetic
#                             attack loop (ebpf-activity.service). Until
#                             2026-08-19 that install was unconditional, so this
#                             flag governed the sims and not the far larger fake
#                             data source next to them: the estate ran a
#                             permanent scripted attack producing ~2,000
#                             alerts/hour, which pinned the executive posture
#                             dial at 93-97 "critical" around the clock.
#   ASSISTANT_URL           the analyst assistant is carried as ExecStart flags
#                           on BOTH server units, so a deploy without it
#                           rewrites those units WITHOUT the flags and ships the
#                           capability switched off. On 2026-09-02 that was one
#                           dim line of output — "assistant off" — against a
#                           deploy where every unit was active, every health
#                           check passed and verify-deploy reported the estate
#                           verified; the assistant was simply gone for 45
#                           minutes until a live browser probe found it. The key
#                           was never the problem: it lives in an operator-owned
#                           assistant.env that survives a redeploy. Only the URL
#                           and the model flags went missing.
#   ASSISTANT_DEEP_MODEL    the THIRD flag on those units — the model used for
#                           sustained sidebar conversations. It is the one with
#                           no default, so an explicit ASSISTANT_URL carrying no
#                           deep model does not keep what is there: it writes
#                           both units without the flag and takes the model off
#                           the estate. Same shape as the entry above, one field
#                           along, which is why every warning below treats all
#                           three fields alike.
#   the `Host` agent        second agent in acme-corp. Skipping it leaves a
#                           version-skewed multi-agent tenant — precisely the
#                           configuration where containment-routing bugs surface.
#
# `make deploy-release` was documented as this entry point but never had a
# recipe: it exited 0 having deployed nothing.
#
# victim_device is deliberately absent. It is the containment TARGET and must
# stay agent-less; giving it an agent invalidates every containment test.

# shellcheck disable=SC2034  # consumed by log()/ok()/die() in lib/common.sh
LOG_TAG="estate"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

# ── Estate definition ──────────────────────────────────────────────────────
CP_SSH="control-plane"
CP_DOMAIN="console.adanianlabs.io"
CP_PRIVATE_IP="172.31.45.193"     # agents dial this for gRPC, not the public IP
ENGINE_SSH="single_tenant_engine"
ENGINE_DOMAIN="engine.adanianlabs.io"

# The sixth host. It receives NO software: it is the containment target, and an
# agent on it would make every containment test meaningless (the agent would be
# both actor and victim). It is still checked, because "we deliberately deployed
# nothing here" and "we forgot this host" look identical without an assertion.
VICTIM_SSH="victim_device"

# Analyst assistant. Opt-in on a box that has never had one, and the key comes
# from the DEPLOYER's environment — never from this file, never from a flag:
#
#   ASSISTANT_URL=https://openweights.example.com/v1 \
#   OPEN_WEIGHT_API_KEY=... ./scripts/deploy/estate.sh
#
# Exported so the provisioners see them. Absent on a box that already runs the
# assistant, the preflight below RECOVERS the URL and the models from the
# RUNNING PROCESS on the target — from its unit only when no process can be
# read — rather than shipping the omission. Absent everywhere, both surfaces
# report the assistant as unconfigured, which is the correct default for a
# security product: no outbound dependency on an inference endpoint unless
# asked for.
#
# Whether the deployer NAMED a model is remembered before the defaults are
# applied. Recovery must not overwrite a model the deployer chose, and it must
# not leave the box on a model it was never deployed with just because
# ASSISTANT_MODEL has a compiled-in default here — "recovered the endpoint,
# silently changed the model" is the same class of failure as the outage above.
ASSISTANT_MODEL_NAMED=0; [[ -n "${ASSISTANT_MODEL:-}" ]] && ASSISTANT_MODEL_NAMED=1
ASSISTANT_DEEP_NAMED=0;  [[ -n "${ASSISTANT_DEEP_MODEL:-}" ]] && ASSISTANT_DEEP_NAMED=1
export ASSISTANT_URL="${ASSISTANT_URL:-}"
export ASSISTANT_MODEL="${ASSISTANT_MODEL:-gpt-oss:120b}"
# Optional second model for sustained conversations in the history sidebar.
# Empty means one model everywhere, which is the default and what every
# deployment had before the split existed.
export ASSISTANT_DEEP_MODEL="${ASSISTANT_DEEP_MODEL:-}"
export OPEN_WEIGHT_API_KEY="${OPEN_WEIGHT_API_KEY:-}"

# ASSISTANT_OFF=1 is the explicit opt-out: it is the only way to REMOVE a
# working assistant from this estate, and it says so on the way past. A deploy
# that turns a capability off has to state that it means to.
ASSISTANT_OFF="${ASSISTANT_OFF:-0}"
if [[ "$ASSISTANT_OFF" == 1 && -n "$ASSISTANT_URL" ]]; then
  die "ASSISTANT_OFF=1 and ASSISTANT_URL are both set — say one thing or the other"
fi

# _assistant_remote_script — the probe that runs ON the target, on its stdin.
#
# It lives in a function of its own rather than inline in the caller because the
# caller has to CAPTURE the reply, and bash 3.2 — what /usr/bin/env bash is on
# the macOS laptops this is deployed from — mis-parses an apostrophe inside a
# here-document that sits inside a command substitution, failing the whole
# script at load with "unexpected EOF". Piping a function's output into ssh
# keeps the substitution free of here-documents.
_assistant_remote_script() {
  cat <<'REMOTE'
unit="$1"; keyfile="$2"

# THREE answers, never two. `systemctl cat` fails IDENTICALLY — exit 1, nothing
# on stdout — for a unit that does not exist and for a systemd that cannot be
# talked to at all, and the second is precisely what a box mid-restart hands
# back ("Failed to connect to bus"). Reading that as "no unit here yet" is the
# 2026-09-02 outage rebuilt one layer down: the run would rewrite the unit
# without the assistant flags and call the box new.
#
# So stderr is captured ALONGSIDE stdout and classified, and only a message that
# actually says the unit is not there counts as absence. Anything unrecognised
# is unreadable — which stops the run — because the failure direction has to be
# "ask a human", not "drop a capability on a guess".
#
# This settles PRESENCE only. The flag VALUES come from somewhere else entirely
# (below): the text `systemctl cat` prints is not what the box is running.
state=unreadable; reason=; src=none; args=
if command -v systemctl >/dev/null 2>&1; then
  resp="$(systemctl cat "$unit" 2>&1)"; rc=$?
  if [ "$rc" -eq 0 ]; then
    state=unit-present
  else
    case "$resp" in
      *"No files found for"*|*"could not be found"*|*"not-found"*)
        state=unit-absent ;;
      *)
        reason="$resp" ;;
    esac
  fi
else
  # No systemctl at all: this is not a box this estate has ever deployed to in
  # the shape it expects, and guessing "no assistant" about it says more than
  # the probe knows.
  reason="systemctl is not on PATH"
fi

# WHERE THE FLAGS COME FROM, and why not from the text above.
#
# `systemctl cat` prints the unit as CONFIGURED — the main file, then every
# drop-in — and this repo's own scripts/ci/verify-deploy.sh spells out why that
# is not an honest source for these flags: a drop-in that sets ExecStart= WINS,
# silently and permanently, and two hand-written ones lived on this estate for
# eight days doing exactly that. Taking an ExecStart= line out of that text gets
# the answer wrong in BOTH directions — it reports an assistant the box is not
# running, and it misses one that it is — and it looks equally confident either
# way.
#
# So the flags are read from the RUNNING process, /proc/<MainPID>/cmdline, which
# is the command line the service is actually executing, drop-ins and all. The
# unit is the FALLBACK, and even then through `systemctl show -p ExecStart`,
# which is systemd's own merged view of unit-plus-drop-ins rather than the raw
# file. Which of the two answered travels back in the record: "what it runs now"
# and "what it would run on the next start" are different claims, and only the
# first one was asked for.
if [ "$state" = unit-present ]; then
  pid="$(systemctl show "$unit" -p MainPID --value 2>/dev/null)"
  pid="${pid#MainPID=}"   # systemd before v230 has no --value; keep the number
  case "$pid" in ''|*[!0-9]*) pid=0 ;; esac
  if [ "$pid" -gt 0 ]; then
    # NUL-separated, one argument per line: this split is exact, where the unit
    # fallback below can only split on spaces.
    if raw="$(tr '\000' '\n' <"/proc/$pid/cmdline" 2>/dev/null)" && [ -n "$raw" ]; then
      args="$raw"; src=process
    elif raw="$(sudo -n cat "/proc/$pid/cmdline" 2>/dev/null | tr '\000' '\n')" && [ -n "$raw" ]; then
      args="$raw"; src=process
    else
      reason="/proc/$pid/cmdline could not be read"
    fi
  else
    reason="the unit is loaded but nothing is running (MainPID 0)"
  fi
  if [ -z "$args" ]; then
    raw="$(systemctl show "$unit" -p ExecStart --value 2>/dev/null |
           sed -n 's/.*argv\[\]=//p' | sed 's/ ; .*//' | head -n1)"
    if [ -n "$raw" ]; then
      args="$(printf '%s\n' "$raw" | tr ' ' '\n')"; src=unit
    fi
  fi
  # A loaded unit that yielded NO command line from either source has not said
  # whether it runs an assistant. An empty argument list finds no flags, and "no
  # flags" would be reported as "no assistant here" — the exact silent omission
  # this preflight exists to stop — so it is unreadable instead.
  if [ -z "$args" ]; then
    state=unreadable; src=none
    reason="${reason:+$reason; }no command line came back from the process or from systemctl show"
  fi
fi

# One flag's value = the argument that follows the flag. An argument list with
# no -assistant-url on it is a real answer — "deployed, deliberately without
# one" — so finding nothing here is not an error.
flag() { printf '%s\n' "$args" | grep -A1 -x -e "$1" | sed -n 2p; }

# The key file is 0600 under a 0700 directory, so an unprivileged stat cannot
# tell "there is no key" from "I am not allowed to look" — and the plan line
# turns the first into an operator-facing claim. Only a reader that COULD have
# seen the file is allowed to say absent:
#   root (via passwordless sudo)  authoritative both ways
#   the login user                a hit proves present; a miss proves nothing
#                                 unless the directory itself was readable
# Everything else is unknown. sudo is -n and never interactive: this runs in a
# preflight, before the deploy has asked the operator for anything.
key=unknown
keydir="$(dirname "$keyfile")"
if sudo -n true >/dev/null 2>&1; then
  if sudo -n test -s "$keyfile" >/dev/null 2>&1; then key=present; else key=absent; fi
elif test -s "$keyfile" 2>/dev/null; then
  key=present
elif [ ! -e "$keydir" ]; then
  key=absent
elif [ -r "$keydir" ] && [ -x "$keydir" ]; then
  key=absent
fi

# The reason travels back through a pipe-delimited record, so it must not carry
# a pipe or a newline of its own — it is a systemd error message, or a path this
# script could not read, neither of which it controls the shape of. It explains
# an unreadable state, and on a readable one it explains why the unit had to
# answer in the running process's place.
reason="$(printf '%s' "$reason" | tr '|\n\r\t' '    ' | cut -c1-120)"

# The marker is printed last and unconditionally: reaching this line is the
# proof that the reads above actually happened on the target.
printf 'EBPF-ASSISTANT-PROBE|%s|%s|%s|%s|%s|%s|%s\n' "$state" "$src" \
  "$(flag -assistant-url)" "$(flag -assistant-model)" "$(flag -assistant-deep-model)" \
  "$key" "$reason"
REMOTE
}

# _assistant_probe <ssh-alias> <unit> <keyfile> — echo
# "state|source|url|model|deep|key|reason" when the box ANSWERED, or return
# non-zero when it could not be asked at all.
#
# A probe has THREE outcomes, and the two that look alike are the dangerous
# pair. An empty url in a reply whose state is unit-present or unit-absent means
# "asked, and there is no assistant here". An ssh that never landed (a box
# mid-restart, a dropped session, a login shell that cannot run bash -s) yields
# an empty url too. Treating the second as the first reproduces the 2026-09-02
# outage exactly, and now under a line claiming the estate was inspected, which
# removes the one signal that would prompt a second look.
#
# So the remote prints a MARKER it can only reach after it has actually looked,
# and a reply without that marker is "could not answer" — never "none". A reply
# WITH the marker can still say unreadable, which the remote decides and this
# function passes through untouched. `source` says which record the flags came
# from — the process the box is running, or the unit it would start next time —
# because those are different claims and the caller reports which one it got.
# The caller decides what an unreadable box means; this function's only job is
# to never blur the two.
#
# Read-only — it starts nothing and writes nothing — so it runs under DRY_RUN
# too, like the reachability loop below it: a dry run that could not tell you
# the assistant is about to be dropped would be the one run where the warning
# matters most.
_assistant_probe() {
  local script out line
  # Materialised, then fed in as a here-string: piping it straight into ssh puts
  # the pipeline under `set -o pipefail`, where a `cat` that takes SIGPIPE
  # because ssh closed stdin first would read as a failed probe.
  script="$(_assistant_remote_script)"
  out="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$1" bash -s -- "$2" "$3" 2>/dev/null <<<"$script")" || return 1
  # Match the marker line rather than the whole reply: a login banner ahead of
  # it is noise, not a failed probe.
  line="$(printf '%s\n' "$out" | grep -m1 '^EBPF-ASSISTANT-PROBE|')" || return 1
  printf '%s\n' "${line#EBPF-ASSISTANT-PROBE|}"
}

# _assistant_probe_state <ssh-alias> <unit> <keyfile> — ALWAYS prints exactly
# one "state|source|url|model|deep|key|reason" record and always succeeds. An
# unreadable box is an answer this preflight has to carry to the operator, not
# an error to be swallowed by `set -e` or lost in a return code, and every
# caller path below is written against a record that is guaranteed to exist.
#
# One retry first. The surfaces are probed while they may still be settling from
# an earlier run, so a single dropped ssh — or a single "Failed to connect to
# bus" from a systemd that is still coming up — is a flap, not a state. A second
# failure is a state we genuinely cannot read, and it is reported as such.
_assistant_probe_state() {
  local out
  if out="$(_assistant_probe "$@")" && [[ "$out" != unreadable\|* ]]; then
    printf '%s\n' "$out"; return 0
  fi
  sleep 3
  if out="$(_assistant_probe "$@")"; then printf '%s\n' "$out"; return 0; fi
  # No marker came back twice. Reachability was already proved for this host by
  # the preflight loop, so this is not "the box is down" — it is "the box took the
  # connection and still could not tell us what it runs", and the message has to
  # say that or the operator goes looking for the wrong fault.
  printf 'unreadable|none|||||%s\n' "ssh connected in preflight but the probe returned nothing (mid-restart, dropped session, or no login shell)"
}

# asst_diverged <field> <host-a> <value-a> <host-b> <value-b> — record that the
# two probed surfaces disagree about one of the fields recovery carries forward.
#
# Newline-joined into a string rather than pushed onto an array because this
# runs under `set -u` on bash 3.2, where expanding an EMPTY array is an unbound
# variable and aborts the preflight — the same reason ASSISTANT_UNKNOWN_WHY is
# shaped this way.
asst_diverged() {
  ASSISTANT_DIVERGENCE="${ASSISTANT_DIVERGENCE:+$ASSISTANT_DIVERGENCE
}$1 — $2: ${3:-<none>} / $4: ${5:-<none>}"
}

# asst_deep_seen <emit> [indent] — one "host: model" line per surface that
# reported a deep model, through the given emitter (warn or dim), indented to
# sit under whatever printed it.
#
# Shared because three places have to print the same list — the change warning,
# the removal warning and the plan line — and a deep model that is about to be
# dropped is exactly the value an operator has to be able to copy back out of
# the output. A list built twice is a list that drifts.
asst_deep_seen() {
  local emit="$1" pad="${2:-  }" line
  while IFS= read -r line; do
    [[ -n "$line" ]] && "$emit" "$pad$line"
  done <<<"$ASSISTANT_DEEP_SEEN"
}

# "tenant=ssh-alias" — acme-corp intentionally appears twice.
AGENTS=(
  "adanian-internal=Tenant_A_agent"
  "acme-corp=Tenant_B_agent"
  "acme-corp=Host"
)

ONLY=""; SKIP_BUILD=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)       ONLY="${2:?}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    -h|--help)    sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

doing() { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

cd "$REPO_ROOT" || die "cannot cd to $REPO_ROOT"

# ── Preflight ──────────────────────────────────────────────────────────────
# Checked BEFORE anything is touched: a half-deployed estate running mixed
# builds is worse than one that never started.
step_header "Preflight"

DEVCHOKE="engine/internal/enforce/devbpf/bpf/devchoke.o"
if [[ -f "$DEVCHOKE" ]]; then
  ok "devchoke.o present — tc device plane will ship"
else
  # Not fatal, but it must be a LOUD choice: without it the agent silently
  # downgrades the device plane to audit-only and still reports success.
  warn "$DEVCHOKE missing — the device plane will silently degrade to audit-only."
  warn "It cannot be built on macOS; copy /opt/ebpf-soc/bpf/devchoke.o off a live agent."
  confirm "deploy anyway, with the device plane degraded?" n || die "stopped"
fi

# The tag that is being deployed should be on the mainline. A release commit
# reachable only through its tag is not on the branch anyone clones.
VERSION="$(git describe --tags --dirty --always 2>/dev/null || echo unknown)"
log "deploying: $VERSION ($(git rev-parse --short HEAD))"
case "$VERSION" in
  *-dirty) warn "work tree is DIRTY — the estate will not match any tag" ;;
esac
if ! git merge-base --is-ancestor HEAD origin/main 2>/dev/null; then
  warn "HEAD is not on origin/main — push it first, or the deployed code is off-branch"
fi

# Reachability first, for every host, before anything is touched. The assistant
# probe below is the second half of the same preflight — it reads the state of
# the units this run is about to overwrite — and it fails the run the same way,
# because a host that answers `true` and then cannot answer what it is running
# is no more deployable than one that never answered at all.
for h in "$CP_SSH" "$ENGINE_SSH" "${AGENTS[@]#*=}"; do
  ssh -o BatchMode=yes -o ConnectTimeout=10 "$h" true 2>/dev/null \
    && ok "ssh $h" || die "cannot reach $h over ssh"
done

# ── Assistant continuity ───────────────────────────────────────────────────
# THE FIFTH SILENT OMISSION (see the header). Deploying without ASSISTANT_URL
# rewrites both server units without the assistant flags, which switches the
# capability off while every unit stays active and every health check passes.
#
# Recovering the value from the target beats failing the preflight because the
# KEYLESS redeploy is the normal case and must stay possible: the key lives in
# an operator-owned assistant.env on the box, and lib.sh rewrites that file only
# when OPEN_WEIGHT_API_KEY is set. Requiring the deployer to re-state a URL the
# target already knows would put a value in every routine deploy that nobody can
# check from here — and a re-stated value typed slightly wrong fails exactly as
# silently as the omission did.
#
# So: recover it, say out loud that it was recovered, and make turning the
# assistant OFF an explicit ASSISTANT_OFF=1. Only probed for the surfaces this
# run actually rewrites — an --only agents run touches neither unit.
#
# What recovery MUST NOT do is treat an unreadable box as an empty one. Three
# outcomes are tracked separately all the way to the operator's screen, because
# only two of them justify a claim about what is on the estate:
#
#   LIVE     answered, and an assistant is configured there  → carry it forward
#   BARE/NEW answered, and none is                           → nothing to preserve
#   UNKNOWN  could not answer                                → we do not know
#
# UNKNOWN is not only "ssh never landed". It also covers a box that took the
# connection and then could not say what it runs — a systemd that is still
# coming up answers `systemctl cat` with a bus error, byte-for-byte as
# indistinguishable from "no such unit" as a dropped session is. Both are the
# same claim ("we do not know"), so they are the same outcome here, and the
# target's own words for which one it was are printed with it.
#
# UNKNOWN with no instruction from the deployer stops the run. This is a deploy
# that is about to overwrite a capability whose current state it cannot read,
# and the two ways out are one word each (ASSISTANT_URL=… or ASSISTANT_OFF=1),
# so guessing buys nothing and costs a silent outage.
ASSISTANT_PROBED=0
ASSISTANT_LIVE_HOSTS=""     # answered: running an assistant now
ASSISTANT_BARE_HOSTS=""     # answered: unit present, no assistant on it
ASSISTANT_NEW_HOSTS=""      # answered: no server unit yet
ASSISTANT_UNKNOWN_HOSTS=""  # could NOT answer: current state unreadable
ASSISTANT_UNKNOWN_WHY=""    # one "host: reason" per unreadable surface
ASSISTANT_KEYED_HOSTS=""    # answered: an assistant.env key is already there
ASSISTANT_KEYUNK_HOSTS=""   # answered about its unit, but the key file was unreadable
ASSISTANT_PROC_HOSTS=""     # answered from the RUNNING process — what it runs now
ASSISTANT_UNITSRC_HOSTS=""  # answered from its unit — what it WOULD run next start
ASSISTANT_UNITSRC_WHY=""    # one "host: reason" per unit-sourced answer
ASSISTANT_DIVERGENCE=""     # one line per field the probed surfaces disagree on
# The deep model is tracked PER HOST, not as one estate-wide value, because it
# is the field most likely to be uneven: it arrived after the assistant did, so
# a surface deployed before it ran none, and the divergence branch below only
# stops a RECOVERY — an explicit ASSISTANT_URL walks straight past it. Saying
# "removed from <every live host>" while quoting one surface's value would name
# hosts that never had one and hide the value the other host actually loses.
ASSISTANT_DEEP_HOSTS=""     # live hosts whose probe reported a deep model
ASSISTANT_DEEP_SEEN=""      # one "host: model" per such host — the value to put back
ASSISTANT_NODEEP_HOSTS=""   # live hosts running the assistant with NO deep model
if doing cp || doing engine; then
  ASSISTANT_PROBED=1
  asst_specs=()
  doing cp     && asst_specs+=("$CP_SSH|ebpf-soc-controlplane|/etc/ebpf-soc/assistant.env")
  doing engine && asst_specs+=("$ENGINE_SSH|ebpf-engine|/etc/ebpf-engine/assistant.env")
  asst_url=""; asst_model=""; asst_deep=""; asst_from=""; asst_from_src=""; asst_seen=0
  for spec in "${asst_specs[@]}"; do
    IFS='|' read -r ah aunit akey <<<"$spec"
    # Always a record, never a return code: the unreadable case has to survive
    # into the report below with the target's own words for WHY, because "could
    # not answer" is the outcome an operator has to be able to act on.
    aout="$(_assistant_probe_state "$ah" "$aunit" "$akey")"
    IFS='|' read -r fstate fsrc fu fm fd fk freason <<<"$aout"
    if [[ "$fstate" == unreadable ]]; then
      ASSISTANT_UNKNOWN_HOSTS="${ASSISTANT_UNKNOWN_HOSTS:+$ASSISTANT_UNKNOWN_HOSTS }$ah"
      ASSISTANT_UNKNOWN_WHY="${ASSISTANT_UNKNOWN_WHY:+$ASSISTANT_UNKNOWN_WHY
}$ah: ${freason:-no reason given}"
      continue
    fi
    # WHICH record answered is part of the answer, not a footnote. The running
    # process is the only honest source for these flags; a surface that could
    # only be read from its unit has told us what it would START next time,
    # which is a weaker claim, and it is reported as one.
    case "$fsrc" in
      process) ASSISTANT_PROC_HOSTS="${ASSISTANT_PROC_HOSTS:+$ASSISTANT_PROC_HOSTS }$ah" ;;
      unit)    ASSISTANT_UNITSRC_HOSTS="${ASSISTANT_UNITSRC_HOSTS:+$ASSISTANT_UNITSRC_HOSTS }$ah"
               ASSISTANT_UNITSRC_WHY="${ASSISTANT_UNITSRC_WHY:+$ASSISTANT_UNITSRC_WHY
}$ah: ${freason:-no reason given}" ;;
      *)       : ;;  # unit-absent: there was neither a process nor a unit to read
    esac
    # The key is three-valued for the same reason the unit is: a login that
    # cannot read a 0600 file under a 0700 directory has not established that
    # the key is missing, and the plan line must not say it has.
    case "${fk:-}" in
      present) ASSISTANT_KEYED_HOSTS="${ASSISTANT_KEYED_HOSTS:+$ASSISTANT_KEYED_HOSTS }$ah" ;;
      absent)  : ;;
      *)       ASSISTANT_KEYUNK_HOSTS="${ASSISTANT_KEYUNK_HOSTS:+$ASSISTANT_KEYUNK_HOSTS }$ah" ;;
    esac
    if [[ -z "${fu:-}" ]]; then
      if [[ "$fstate" == unit-present ]]; then
        ASSISTANT_BARE_HOSTS="${ASSISTANT_BARE_HOSTS:+$ASSISTANT_BARE_HOSTS }$ah"
      else
        ASSISTANT_NEW_HOSTS="${ASSISTANT_NEW_HOSTS:+$ASSISTANT_NEW_HOSTS }$ah"
      fi
      continue
    fi
    ASSISTANT_LIVE_HOSTS="${ASSISTANT_LIVE_HOSTS:+$ASSISTANT_LIVE_HOSTS }$ah"
    if [[ -n "${fd:-}" ]]; then
      ASSISTANT_DEEP_HOSTS="${ASSISTANT_DEEP_HOSTS:+$ASSISTANT_DEEP_HOSTS }$ah"
      ASSISTANT_DEEP_SEEN="${ASSISTANT_DEEP_SEEN:+$ASSISTANT_DEEP_SEEN
}$ah: $fd"
    else
      ASSISTANT_NODEEP_HOSTS="${ASSISTANT_NODEEP_HOSTS:+$ASSISTANT_NODEEP_HOSTS }$ah"
    fi
    if (( ! asst_seen )); then
      asst_seen=1; asst_from="$ah"; asst_from_src="$fsrc"
      asst_url="$fu"; asst_model="${fm:-}"; asst_deep="${fd:-}"
    else
      # EVERY field recovery carries forward is compared, not just the URL.
      # Recovery exports three, so a model that differs between the surfaces is
      # exactly as unrecoverable as an endpoint that does: whichever surface
      # happened to be probed first would win and the other would be silently
      # retuned to a model it was never deployed with. That is the failure the
      # header calls "recovered the endpoint, silently changed the model", and
      # comparing one field while carrying three is how it gets through.
      [[ "$fu" == "$asst_url"   ]] || asst_diverged "endpoint"   "$asst_from" "$asst_url"   "$ah" "$fu"
      [[ "$fm" == "$asst_model" ]] || asst_diverged "model"      "$asst_from" "$asst_model" "$ah" "$fm"
      [[ "$fd" == "$asst_deep"  ]] || asst_diverged "deep model" "$asst_from" "$asst_deep"  "$ah" "$fd"
    fi
  done

  # Report the probe itself before anything acts on it, one line per outcome, so
  # "we looked and found none" and "we could not look" can never reach the
  # operator as the same sentence. Silence is what let them merge.
  if [[ -n "$ASSISTANT_LIVE_HOSTS" ]]; then
    ok "assistant probe: $ASSISTANT_LIVE_HOSTS answered — an assistant is configured there"
  fi
  if [[ -n "$ASSISTANT_BARE_HOSTS" ]]; then
    ok "assistant probe: $ASSISTANT_BARE_HOSTS answered — unit present, no assistant on it"
  fi
  if [[ -n "$ASSISTANT_NEW_HOSTS" ]]; then
    ok "assistant probe: $ASSISTANT_NEW_HOSTS answered — no server unit yet, nothing to preserve"
  fi
  if [[ -n "$ASSISTANT_PROC_HOSTS" ]]; then
    ok "assistant probe: read from the RUNNING process on $ASSISTANT_PROC_HOSTS (/proc/<pid>/cmdline)"
  fi
  if [[ -n "$ASSISTANT_UNITSRC_HOSTS" ]]; then
    warn "assistant probe: $ASSISTANT_UNITSRC_HOSTS answered from its UNIT, not from a running"
    warn "process — that is what it would START next time, and the two differ whenever the unit"
    warn "changed after the service last started:"
    while IFS= read -r awhy; do
      [[ -n "$awhy" ]] && warn "  $awhy"
    done <<<"$ASSISTANT_UNITSRC_WHY"
  fi
  if [[ -n "$ASSISTANT_DIVERGENCE" ]]; then
    # Named, and named per FIELD. "the surfaces differ" with no list sends an
    # operator to compare two long ExecStart lines by eye; this says which of
    # the three values disagree and what each surface holds.
    warn "assistant probe: the probed surfaces do NOT run the same assistant —"
    while IFS= read -r adiff; do
      [[ -n "$adiff" ]] && warn "  $adiff"
    done <<<"$ASSISTANT_DIVERGENCE"
  fi
  if [[ -n "$ASSISTANT_KEYUNK_HOSTS" ]]; then
    warn "assistant probe: $ASSISTANT_KEYUNK_HOSTS answered about its unit, but its key file was not"
    warn "readable from the login account — whether a key is there is UNKNOWN, not absent"
  fi
  if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
    # Named "took the connection and could not answer", not "unreachable": the
    # reachability loop above already proved ssh works on this host, so an
    # operator told "did not answer" would go and test the wrong thing.
    err "assistant probe: $ASSISTANT_UNKNOWN_HOSTS took the connection but could NOT report its"
    err "assistant state — what it runs now is unknown, and this run rewrites its unit:"
    while IFS= read -r awhy; do
      [[ -n "$awhy" ]] && err "  $awhy"
    done <<<"$ASSISTANT_UNKNOWN_WHY"
  fi

  if [[ -n "$ASSISTANT_URL" ]]; then
    # Explicit wins, always, so neither an unreadable box nor a divergence can
    # change the outcome — they only narrow what can honestly be said about what
    # is being replaced. The endpoint and model "was" values are attributed to
    # the ONE surface they were read from: when the surfaces diverge there is no
    # single "before", and one surface's endpoint printed as if it were the
    # whole estate's is the untrue claim this block exists to avoid. The deep
    # model, which is the field most often uneven, is listed per host instead —
    # naming a value that has to be copied back out of this output.
    if [[ -n "$asst_url" && "$asst_url" != "$ASSISTANT_URL" ]]; then
      warn "assistant endpoint CHANGES on $ASSISTANT_LIVE_HOSTS to $ASSISTANT_URL (was $asst_url on $asst_from)"
    fi
    if [[ -n "$asst_model" && "$asst_model" != "$ASSISTANT_MODEL" ]]; then
      # The model changes even when nobody named one: ASSISTANT_MODEL has a
      # compiled-in default at the top of this file, and an explicit URL takes
      # that default with it. Say so rather than let the box change models under
      # a deploy that only meant to move the endpoint.
      warn "assistant MODEL changes on $ASSISTANT_LIVE_HOSTS to $ASSISTANT_MODEL (was $asst_model on $asst_from)"
      (( ASSISTANT_MODEL_NAMED )) || warn "  — that is this script's default, not a model you named; set ASSISTANT_MODEL to keep $asst_model"
    fi
    # The DEEP model is the THIRD field these units carry, and it is the only
    # one that can go to empty: ASSISTANT_MODEL has a compiled-in default, so a
    # deploy can only ever change it, while ASSISTANT_DEEP_MODEL defaults to
    # nothing and an explicit URL without it rewrites both units WITHOUT the
    # flag — taking a model the estate is running off the estate. Warning only
    # when two non-empty values differ would say nothing in exactly that case,
    # which is the 2026-09-02 failure (a capability removed by omission under a
    # deploy where every unit is active) reproduced on the third field. So
    # removal is named, per host, with the value needed to undo it.
    if [[ -z "$ASSISTANT_DEEP_MODEL" ]]; then
      if [[ -n "$ASSISTANT_DEEP_HOSTS" ]]; then
        warn "assistant DEEP model is REMOVED from $ASSISTANT_DEEP_HOSTS — you named a URL but no"
        warn "ASSISTANT_DEEP_MODEL, and the flag is written from that variable alone:"
        asst_deep_seen warn
        warn "  — sidebar conversations fall back to $ASSISTANT_MODEL; re-state the model above to keep it"
      fi
    else
      # Two different changes, and a host can only be in one of them: changing
      # a deep model and gaining one are different things to check afterwards,
      # and an uneven estate — one surface with a deep model, one without —
      # makes both true in the same run. Only the hosts whose value actually
      # differs are listed as changing; a host already on the named model is
      # not changing, and padding the list is how it stops being read.
      asst_deep_changing=""; asst_deep_was=""
      while IFS= read -r aline; do
        [[ -n "$aline" ]] || continue
        [[ "${aline#*: }" == "$ASSISTANT_DEEP_MODEL" ]] && continue
        asst_deep_changing="${asst_deep_changing:+$asst_deep_changing }${aline%%:*}"
        asst_deep_was="${asst_deep_was:+$asst_deep_was
}$aline"
      done <<<"$ASSISTANT_DEEP_SEEN"
      if [[ -n "$asst_deep_changing" ]]; then
        warn "assistant DEEP model changes on $asst_deep_changing to $ASSISTANT_DEEP_MODEL, from:"
        while IFS= read -r aline; do
          [[ -n "$aline" ]] && warn "  $aline"
        done <<<"$asst_deep_was"
      fi
      if [[ -n "$ASSISTANT_NODEEP_HOSTS" ]]; then
        # Gaining one is not a silent loss, but it is still a change to what the
        # box runs, and it is said for the same reason the losses are.
        warn "assistant DEEP model is ADDED on $ASSISTANT_NODEEP_HOSTS ($ASSISTANT_DEEP_MODEL) — one model everywhere there before"
      fi
    fi
    if [[ -n "$ASSISTANT_DIVERGENCE" ]]; then
      warn "the fields listed above as differing are unified onto the values given here"
    fi
    if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
      warn "$ASSISTANT_UNKNOWN_HOSTS was not readable — whatever it runs now is overwritten unseen"
    fi
  elif [[ "$ASSISTANT_OFF" == 1 ]]; then
    # Removal is the stated intent, so an unreadable box does not change the
    # action either — only the accuracy of the list of what loses the assistant.
    if [[ -n "$ASSISTANT_LIVE_HOSTS" ]]; then
      warn "ASSISTANT_OFF=1 — the assistant will be REMOVED from $ASSISTANT_LIVE_HOSTS"
      # All three fields go, so all three are named: "one deploy back" is only
      # true if the operator can still see the values to deploy back WITH, and
      # the deep model is the one nobody remembers was set.
      warn "  (was ${asst_model:-<no model flag>} via $asst_url on $asst_from)"
      if [[ -n "$ASSISTANT_DEEP_SEEN" ]]; then
        warn "  sidebar model, which goes with it:"
        asst_deep_seen warn
      fi
      warn "(the key file stays; only the ExecStart flags go, so it is one deploy back)"
    fi
    if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
      warn "ASSISTANT_OFF=1 — $ASSISTANT_UNKNOWN_HOSTS could not be read, so whether it had one is"
      warn "unknown; it is deployed without either way, which is what was asked for"
    fi
    if [[ -z "$ASSISTANT_LIVE_HOSTS$ASSISTANT_UNKNOWN_HOSTS" ]]; then
      ok "ASSISTANT_OFF=1 — every probed surface answered and none runs one; nothing to remove"
    fi
  elif [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
    # Nothing to carry forward, and no instruction to follow. Continuing means
    # rewriting the unit from a guess, and the guess that costs an outage —
    # "probably had none" — is the one a failed probe hands you. A surface that
    # answered is no help either: the surfaces are allowed to differ (see the
    # divergence branch below), so a value read from one cannot be assumed of
    # the other.
    err "cannot read the assistant state on $ASSISTANT_UNKNOWN_HOSTS, and this run rewrites its unit"
    err "a unit rewritten without the flags ships the assistant OFF while every health check passes"
    die "refusing to guess — retry when the box answers, or state it: ASSISTANT_URL=… / ASSISTANT_OFF=1"
  elif [[ -z "$ASSISTANT_LIVE_HOSTS" ]]; then
    ok "assistant: every probed surface answered and none runs one — nothing to preserve"
  elif [[ -n "$ASSISTANT_DIVERGENCE" ]]; then
    # Two surfaces, two configurations: there is no single set of values to
    # carry forward, and recovering from whichever answered first would silently
    # repoint — or re-model — the other. The deployer has to say. Which fields
    # differ was printed above, per field and per surface, so this line does not
    # repeat them.
    err "the probed surfaces ($ASSISTANT_LIVE_HOSTS) do not run the same assistant, so there is"
    err "no single configuration to recover; taking one surface's values would silently change"
    err "the other — see the differing fields listed above"
    die "state it explicitly: ASSISTANT_URL=… (with ASSISTANT_MODEL / ASSISTANT_DEEP_MODEL), or ASSISTANT_OFF=1"
  else
    export ASSISTANT_URL="$asst_url"
    (( ASSISTANT_MODEL_NAMED )) || [[ -z "$asst_model" ]] || export ASSISTANT_MODEL="$asst_model"
    (( ASSISTANT_DEEP_NAMED ))  || export ASSISTANT_DEEP_MODEL="$asst_deep"
    # Named with the surface AND the record the values actually came from. Every
    # live surface agreed — divergence dies above — so one name is enough, and
    # it is the one that can be checked by hand if the line looks wrong.
    case "$asst_from_src" in
      process) asst_src_label="the running process on $asst_from" ;;
      *)       asst_src_label="the UNIT on $asst_from — nothing was running there to read" ;;
    esac
    warn "ASSISTANT_URL was not set — RECOVERED from $asst_src_label:"
    warn "  $ASSISTANT_MODEL via $ASSISTANT_URL${ASSISTANT_DEEP_MODEL:+  (sidebar: $ASSISTANT_DEEP_MODEL)}"
    # Recovery is not automatically continuity. A deployer who named a model —
    # either of them — without naming a URL still CHANGES what the estate runs,
    # and the line above prints only what will run next: "was X" has to be said
    # here or a model swap rides in under the word RECOVERED. Named per field,
    # for the same reason the explicit-URL branch does it per field.
    if (( ASSISTANT_MODEL_NAMED )) && [[ -n "$asst_model" && "$asst_model" != "$ASSISTANT_MODEL" ]]; then
      warn "  — MODEL changes on $ASSISTANT_LIVE_HOSTS: was $asst_model on $asst_from, you named $ASSISTANT_MODEL"
    fi
    if (( ASSISTANT_DEEP_NAMED )) && [[ "$asst_deep" != "$ASSISTANT_DEEP_MODEL" ]]; then
      warn "  — DEEP model changes on $ASSISTANT_LIVE_HOSTS: was ${asst_deep:-none} on $asst_from, you named $ASSISTANT_DEEP_MODEL"
    fi
    warn "the assistant stays ON. To remove it deliberately, deploy with ASSISTANT_OFF=1."
    if [[ -n "$ASSISTANT_DEEP_MODEL" ]]; then
      # This path can never DROP the deep model: an empty ASSISTANT_DEEP_MODEL
      # is indistinguishable from an unset one, so it reads as "recover it".
      # That is deliberate — omission must not remove a capability — but it
      # leaves the operator needing the one route that does, spelled out.
      warn "to drop only the sidebar model, deploy with an explicit ASSISTANT_URL and no ASSISTANT_DEEP_MODEL."
    fi
    # Both surfaces are meant to carry the same assistant, so a one-sided
    # recovery is a repair — but it is still a host GAINING a capability it did
    # not have, which nobody should discover afterwards. Named, not counted:
    # only a surface that ANSWERED "none" can be said to be gaining one.
    # Joined with the same guard used everywhere above rather than an
    # unconditional separator: either list can be empty, and a stray space is
    # how the line ends up naming a host called "" to a reader skimming it.
    asst_gaining="$ASSISTANT_BARE_HOSTS"
    if [[ -n "$ASSISTANT_NEW_HOSTS" ]]; then
      asst_gaining="${asst_gaining:+$asst_gaining }$ASSISTANT_NEW_HOSTS"
    fi
    if [[ -n "$asst_gaining" ]]; then
      warn "$asst_gaining had none and will now get it too"
    fi
  fi
fi

printf '\n'
log "plan:"
doing cp     && dim "control plane   $CP_SSH      TLS=1 DATA_MODE=none  $CP_DOMAIN"
doing engine && dim "engine          $ENGINE_SSH  TLS=1                 $ENGINE_DOMAIN"
doing agents && for a in "${AGENTS[@]}"; do dim "agent           ${a#*=}  tenant=${a%%=*}"; done
dim "victim_device   SKIPPED — containment target, must stay agent-less"
# The key line has to distinguish "no key anywhere" from "no key in MY
# environment, and one already on the box". They were printed identically, so a
# normal keyless redeploy of a fully working assistant read as broken — which is
# how you learn to ignore the line that later reports a real outage. And an
# unreadable box gets neither claim: nobody can say a key is absent from a host
# that never answered.
asst_key_note=""
# A host whose UNIT could not be read never had its key read either, and a host
# that answered about its unit can still have had an unreadable key file. Both
# belong on the same "we do not know" list.
asst_key_unreadable="$ASSISTANT_KEYUNK_HOSTS"
if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
  asst_key_unreadable="${asst_key_unreadable:+$asst_key_unreadable }$ASSISTANT_UNKNOWN_HOSTS"
fi
if [[ -z "$OPEN_WEIGHT_API_KEY" ]]; then
  if ! (( ASSISTANT_PROBED )); then
    asst_key_note="  (key not checked — this run rewrites no server unit)"
  elif [[ -n "$asst_key_unreadable" ]]; then
    asst_key_note="  (key state UNKNOWN on $asst_key_unreadable${ASSISTANT_KEYED_HOSTS:+; present on $ASSISTANT_KEYED_HOSTS})"
  elif [[ -n "$ASSISTANT_KEYED_HOSTS" ]]; then
    asst_key_note="  (key already on $ASSISTANT_KEYED_HOSTS, left untouched)"
  else
    asst_key_note="  (NO KEY — every probed surface answered and none has one; will report unavailable)"
  fi
fi
if ! (( ASSISTANT_PROBED )); then
  dim "assistant       unchanged — not probed, this run rewrites no server unit"
elif [[ -n "$ASSISTANT_URL" ]]; then
  dim "assistant       $ASSISTANT_MODEL via $ASSISTANT_URL$asst_key_note"
  if [[ -n "$ASSISTANT_DEEP_MODEL" ]]; then
    dim "                $ASSISTANT_DEEP_MODEL for sidebar conversations (panels stay on $ASSISTANT_MODEL)"
  elif [[ -n "$ASSISTANT_DEEP_SEEN" ]]; then
    # The plan is the last thing read before the confirm prompt, so the field
    # that is DISAPPEARING has to appear on it too. Printing the deep model only
    # when one is set makes its removal the one change the plan is silent about.
    dim "                sidebar model REMOVED from $ASSISTANT_DEEP_HOSTS — one model everywhere:"
    asst_deep_seen dim "                  "
  fi
  if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
    dim "                $ASSISTANT_UNKNOWN_HOSTS could not be read — its previous setting is overwritten unseen"
  fi
elif [[ "$ASSISTANT_OFF" == 1 ]]; then
  dim "assistant       OFF BY REQUEST (ASSISTANT_OFF=1)${ASSISTANT_LIVE_HOSTS:+ — removed from $ASSISTANT_LIVE_HOSTS}"
  if [[ -n "$ASSISTANT_UNKNOWN_HOSTS" ]]; then
    dim "                $ASSISTANT_UNKNOWN_HOSTS could not be read — unknown whether it had one"
  fi
else
  # Reached only when every probed surface ANSWERED and none had an assistant:
  # the unreadable case dies above rather than arriving here, which is what
  # entitles this line to say the estate was checked.
  dim "assistant       off — every probed surface answered, none has one (set ASSISTANT_URL to enable)"
fi
printf '\n'
confirm "deploy $VERSION to the production estate?" n || die "stopped"

# ── Build ──────────────────────────────────────────────────────────────────
# `make build-linux`, never `go build ./cmd/engine`: the engine serves its
# console from go:embed, staged from web/dist by the Makefile's `web` target.
# A plain go build compiles fine and silently ships STALE UI.
if (( ! SKIP_BUILD )) && [[ -z "$ONLY" || "$ONLY" != "verify" ]]; then
  step_header "Build (make build-linux — go:embed needs the web target)"
  run make build-linux
fi

# ── Control plane ──────────────────────────────────────────────────────────
if doing cp; then
  step_header "Control plane — $CP_DOMAIN"
  run env TLS=1 DATA_MODE=none TARGET_HOST="$CP_DOMAIN" SSH_HOST="$CP_SSH" \
    ./scripts/deploy/multi-tenant-ubuntu.sh
fi

# ── Single-tenant engine ───────────────────────────────────────────────────
if doing engine; then
  step_header "Engine — $ENGINE_DOMAIN"
  # DEVCHOKE=1 so the single-tenant engine gets a real tc data plane, like the
  # agents do. Without it provision_engine takes the noop branch: the console
  # reports "Plane Noop / Links 0 / data plane OFFLINE" and every device
  # containment is recorded and drops nothing. That was honest but it was also
  # a capability the box could have had — the compile happens on the target and
  # the agents have run it since they were built.
  run env TLS=1 DEVCHOKE=1 TARGET_HOST="$ENGINE_DOMAIN" SSH_HOST="$ENGINE_SSH" \
    ./scripts/deploy/single-tenant-ubuntu.sh
fi

# ── Agents ─────────────────────────────────────────────────────────────────
if doing agents; then
  for a in "${AGENTS[@]}"; do
    tenant="${a%%=*}"; host="${a#*=}"
    step_header "Agent — $host (tenant $tenant)"
    run make deploy-agent TENANT="$tenant" AGENT_HOST="$host" \
      CP_SSH="$CP_SSH" CP_IP="$CP_PRIVATE_IP" DATA_MODE=none
  done
fi

# ── Verify ─────────────────────────────────────────────────────────────────
# Always runs, even with --only: the point of the whole exercise is not that the
# scripts exited 0 but that the estate is serving and every host runs the same
# build. A deploy reporting success while half the fleet runs the previous
# binary is the failure this catches, and it has happened here.
step_header "Verify — victim_device stays agent-less"
# The same three outcomes as the assistant preflight, and this claim carries
# more weight than that one did: "agent-less" is the premise every containment
# result on this rig rests on. The old spelling was
#   systemctl is-active ebpf-agent 2>/dev/null || true
# which turns a systemd that cannot be talked to into an empty string and then
# prints "agent-less (ebpf-agent: absent)" — an affirmative claim assembled out
# of a read that never happened. is-active exits non-zero for every state except
# active, so its OUTPUT is the answer and its stderr is part of that answer.
if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$VICTIM_SSH" true 2>/dev/null; then
  warn "$VICTIM_SSH did not answer ssh — NOT confirmed agent-less; containment results"
  warn "from this rig are unverified until it does"
else
  # `|| true` IS LOad-BEARING, and it does not reintroduce the lie this block was
  # rewritten to remove. `systemctl is-active` exits non-zero for every state
  # except active — 3 for inactive, 4 for a unit that is not installed at all,
  # which is precisely the state this host is meant to be in. Under the
  # `set -euo pipefail` this script inherits, that status aborts the assignment
  # and takes the whole deploy with it: measured 2026-09-08, the estate deployed
  # cleanly and then died here with exit 4 on a victim_device that was correctly
  # agent-less, before verify-deploy.sh or the endpoint summary ever ran.
  # The OUTPUT is the answer (that is this block's whole design), so the status
  # is discarded deliberately and the case below still classifies an empty reply
  # as "systemd did not answer" rather than as agent-less.
  victim_agent="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$VICTIM_SSH" \
    'systemctl is-active ebpf-agent 2>&1' 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
  case "$victim_agent" in
    active|activating|reloading)
      err "$VICTIM_SSH IS RUNNING AN AGENT (ebpf-agent: $victim_agent) — it must stay a"
      err "non-agent containment target, or the agent is both actor and victim"
      err "every containment result from this rig is suspect until that is removed"
      exit 1 ;;
    inactive|failed|unknown|deactivating)
      # A systemd state name back means systemd answered, and none of these
      # states runs anything. "unknown" is the unit not being installed at all,
      # which is exactly the state this host is meant to be in.
      ok "$VICTIM_SSH agent-less (ebpf-agent: $victim_agent)" ;;
    *)
      # Anything else is systemd NOT answering — "Failedtoconnecttobus..." once
      # the whitespace is stripped — or an empty reply. Neither of those says
      # the box is agent-less, so neither is allowed to print that it is.
      warn "$VICTIM_SSH answered ssh but not about ebpf-agent (${victim_agent:-empty reply})"
      warn "— NOT confirmed agent-less; containment results from this rig are unverified" ;;
  esac
  # Reported verbatim rather than defaulted to "absent" for the same reason: this
  # line is informational, and an informational line that invents a state is how
  # the one above learned to lie.
  # Same shape, same reason: a stopped victim-http exits 3 and would abort here.
  victim_http="$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$VICTIM_SSH" \
    'systemctl is-active victim-http 2>&1' 2>/dev/null | head -n1 | tr -d '[:space:]' || true)"
  dim "victim-http: ${victim_http:-no reply}"
fi

step_header "Verify"
run env CP_HOST="$CP_SSH" ENGINE_HOST="$ENGINE_SSH" \
  AGENT_HOSTS="${AGENTS[*]}" \
  ./scripts/ci/verify-deploy.sh

step_header "Endpoints"
# Both surfaces are deployed with TLS=1 above, so https is the address that
# works — printing the plaintext one would hand out a URL that redirects at best.
endpoint console  "https://$CP_DOMAIN/"
endpoint keycloak "https://$CP_DOMAIN/admin/"
endpoint engine   "https://$ENGINE_DOMAIN/"
for a in "${AGENTS[@]}"; do
  endpoint agent "${a#*=}" "tenant ${a%%=*}"
done
endpoint victim "$VICTIM_SSH" "containment target, no agent by design"
printf '\n'
dim "An agent's own console binds 127.0.0.1:8080 and is not published. Reach one with"
dim "  ssh -L 8080:127.0.0.1:8080 <agent-host>   then http://127.0.0.1:8080/"
dim "  user admin; password: sudo cat /etc/ebpf-soc/agent-console.env"
dim "Console and Keycloak logins are in .deploy-build/credentials-<host>.txt (0600)."
# The probe suite's personas are console accounts like any other, so they land
# in that same file — and it is the ONLY copy, because the provisioner generates
# their passwords and never prints them twice. Named here with the environment
# variables the suite reads, so nobody has to guess which line maps to which
# variable; checked rather than asserted, because an estate provisioned before
# the personas existed has neither account and their probes skip.
cred_file="$REPO_ROOT/.deploy-build/credentials-$CP_DOMAIN.txt"
if [[ -f "$cred_file" ]] && grep -qi 'read-only\|cross-tenant-responder' "$cred_file"; then
  dim "Probe personas are in that file too: read-only → PROBE_RO_USER/PROBE_RO_PASSWORD,"
  dim "  cross-tenant-responder → PROBE_XR_USER/PROBE_XR_PASSWORD (web/e2e/probe/personas)."
else
  dim "No read-only / cross-tenant-responder account on this estate — the persona"
  dim "  probes (PROBE_RO_*, PROBE_XR_*) will skip, not fail."
fi

printf '\n'
ok "estate deployed and verified: $VERSION"
dim "built_at from /api/version is the COMMIT time, not the build time — it reads"
dim "stale even on a good deploy. Compare on-box sha256sum against .deploy-build/."
