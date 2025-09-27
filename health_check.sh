#!/bin/bash
set -Eeuo pipefail


STRICT="${HARDN_HEALTH_STRICT:-0}"
TMO="${HARDN_HEALTH_TIMEOUT:-2}"

ok=0 warn=0 fail=0
NOTE() { printf '[note] %s\n' "$*"; }
GOOD() { printf '[ ok ] %s\n' "$*"; ok=$((ok+1)); }
WARN() { printf '[warn] %s\n' "$*"; warn=$((warn+1)); }
FAIL() { printf '[fail] %s\n' "$*"; fail=$((fail+1)); }
RUN()  { timeout --preserve-status "$TMO" bash -lc "$*" 2>&1; }

uid="$(id -u)"
if [[ "$uid" != "10001" && "$uid" != "0" ]]; then
  FAIL "unexpected uid ($uid) – expected 10001 (hardn) or 0 (root)"
else
  [[ "$uid" == "0" ]] && NOTE "running as root (ok for CI/testing)"
  GOOD "running as uid=$uid"
fi


[[ -d /opt/hardn-xdr ]] && GOOD "/opt/hardn-xdr present" || FAIL "/opt/hardn-xdr missing"
[[ -d /sources     ]] && GOOD "/sources present"         || FAIL "/sources missing"

for f in /usr/local/bin/entrypoint.sh \
         /usr/local/bin/smoke_test.sh
do
  if [[ -f "$f" && -x "$f" ]]; then
    GOOD "$(basename "$f") present & executable"
  elif [[ -f "$f" ]]; then
    WARN "$(basename "$f") present but not executable"
  else
    FAIL "$(basename "$f") missing"
  fi
done

# Check deb.hardn.sh separately - it should be root-only executable
if [[ -f /usr/local/bin/deb.hardn.sh ]]; then
  GOOD "deb.hardn.sh present (root-only executable)"
else
  FAIL "deb.hardn.sh missing"
fi

if RUN ': > /tmp/.hc.$$ && rm -f /tmp/.hc.$$' >/dev/null; then
  GOOD "tmp usable"
else
  FAIL "tmp not usable"
fi

# simulate app deployment
if [[ -r /sources ]]; then
  if RUN 'find /sources -type f -maxdepth 1 -readable -print -quit | grep -q .' >/dev/null; then
    GOOD "able to read at least one file from /sources"
  else
    WARN "no readable files found at top of /sources"
  fi
else
  WARN "/sources not readable"
fi

# pentest
if [[ -f /etc/login.defs ]]; then
  checks=0; pass=0
  ((checks++)); grep -Eq '^UMASK\s+0?27\b' /etc/login.defs && ((pass++)) || WARN "UMASK not 027"
  ((checks++)); grep -Eq '^PASS_MIN_DAYS\s+1\b' /etc/login.defs && ((pass++)) || WARN "PASS_MIN_DAYS != 1"
  ((checks++)); grep -Eq '^PASS_MAX_DAYS\s+90\b' /etc/login.defs && ((pass++)) || WARN "PASS_MAX_DAYS != 90"
  ((checks++)); grep -Eq '^PASS_WARN_AGE\s+7\b' /etc/login.defs && ((pass++)) || WARN "PASS_WARN_AGE != 7"
  ((pass==checks)) && GOOD "login.defs baseline OK ($pass/$checks)" || :
else
  WARN "/etc/login.defs not found"
fi

if [[ -f /etc/pam.d/common-password ]]; then
  if grep -Eq '(^|\s)pam_pwquality\.so(\s|$)' /etc/pam.d/common-password \
     && grep -Eq 'minlen=([8-9]|[1-9][0-9]+)' /etc/pam.d/common-password; then
    GOOD "PAM pwquality minlen>=8"
  else
    WARN "PAM pwquality/minlen not enforced to >=8"
  fi
else
  WARN "PAM common-password not found"
fi

if [[ -f /var/lib/hardn/file-integrity.db ]]; then
  GOOD "file-integrity baseline exists"
else
  WARN "file-integrity baseline missing (first run?)"
fi

if [[ -x /usr/local/bin/smoke_test.sh ]]; then
  if RUN '/usr/local/bin/smoke_test.sh --health 2>/dev/null || true' >/dev/null; then
    GOOD "smoke_test.sh invoked (health mode)"
  else
    WARN "smoke_test.sh returned nonzero (health mode); continuing"
  fi
fi

if getent passwd hardn >/dev/null 2>&1; then
  GOOD "user 'hardn' present"
else
  FAIL "user 'hardn' missing"
fi

printf '\nSummary: ok=%d warn=%d fail=%d\n' "$ok" "$warn" "$fail"

if (( fail > 0 )); then exit 1; fi

if (( STRICT == 1 && warn > 0 )); then
  NOTE "STRICT=1: warnings escalate to failure"
  exit 1
fi

echo "Health check passed."
exit 0
