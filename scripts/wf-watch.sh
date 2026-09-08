#!/usr/bin/env bash
# Live view of a running Claude Code workflow: which cluster is doing what, right now.
#   ./wf-watch.sh            # watches the newest workflow run
#   ./wf-watch.sh <runId>    # watches a specific one
BASE="$HOME/.claude/projects/-Users-jeff-Code-eBPF-SOC/1bfad455-5b5b-40f0-bb04-6154f1c73d0a/subagents/workflows"
DIR="${1:+$BASE/$1}"; DIR="${DIR:-$(ls -td "$BASE"/wf_* 2>/dev/null | head -1)}"
[ -d "$DIR" ] || { echo "no workflow run found under $BASE"; exit 1; }

while true; do
  printf "\033[2J\033[H"
  echo "workflow: $(basename "$DIR")    $(date '+%H:%M:%S')"
  echo "done: $(grep -c '"type":"result"' "$DIR/journal.jsonl" 2>/dev/null) of $(grep -c '"type":"started"' "$DIR/journal.jsonl" 2>/dev/null) started"
  echo
  for f in "$DIR"/agent-*.jsonl; do
    [ -e "$f" ] || continue
    python3 - "$f" <<'PY'
import json,sys,os,time
f=sys.argv[1]
task=last=""; n=0
try:
    for line in open(f, errors="ignore"):
        try: d=json.loads(line)
        except: continue
        m=d.get("message") or {}
        for c in (m.get("content") or []):
            if not isinstance(c,dict): continue
            if c.get("type")=="text" and d.get("type")=="user" and not task:
                task=" ".join(c["text"].split())[:70]
            if c.get("type")=="tool_use":
                n+=1
                inp=c.get("input") or {}
                last=f'{c.get("name")}: ' + " ".join(str(
                    inp.get("description") or inp.get("file_path") or inp.get("pattern") or inp.get("command") or ""
                ).split())[:64]
except FileNotFoundError:
    pass
age=int(time.time()-os.path.getmtime(f))
mark="working" if age < 90 else f"idle {age}s"
print(f"  [{mark:>9}] {n:>3} steps  {last or '(starting)'}")
PY
  done
  echo
  echo "  (ctrl-c to stop)"
  sleep 5
done
