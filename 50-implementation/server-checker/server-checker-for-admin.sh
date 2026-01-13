#!/usr/bin/env bash
set -euo pipefail

#######################################
# Component detection
#######################################
HAS_POSTFIX=0
HAS_DOVECOT=0

command -v postconf >/dev/null 2>&1 && HAS_POSTFIX=1
command -v dovecot  >/dev/null 2>&1 && HAS_DOVECOT=1

#######################################
# Default config locations (overridable)
#######################################
POSTFIX_MAIN="/etc/postfix/main.cf"
POSTFIX_MASTER="/etc/postfix/master.cf"

DOVECOT_AUTH="/etc/dovecot/conf.d/10-auth.conf"
DOVECOT_SSL="/etc/dovecot/conf.d/10-ssl.conf"
DOVECOT_MAIN="/etc/dovecot/dovecot.conf"

OUTFILE=""

#######################################
# CLI parsing
#######################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUTFILE="$2"; shift 2 ;;
    --postfix-main) POSTFIX_MAIN="$2"; shift 2 ;;
    --postfix-master) POSTFIX_MASTER="$2"; shift 2 ;;
    --dovecot-auth) DOVECOT_AUTH="$2"; shift 2 ;;
    --dovecot-ssl) DOVECOT_SSL="$2"; shift 2 ;;
    --dovecot-main) DOVECOT_MAIN="$2"; shift 2 ;;
    -h|--help)
      cat <<EOF
Usage: $0 [options]

Options:
  -o <file>                Write JSON report to file
  --postfix-main <path>    Path to Postfix main.cf
  --postfix-master <path>  Path to Postfix master.cf
  --dovecot-auth <path>    Path to Dovecot 10-auth.conf
  --dovecot-ssl <path>     Path to Dovecot 10-ssl.conf
  --dovecot-main <path>    Path to dovecot.conf (monolithic)
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

#######################################
# Output helpers
#######################################
FIRST_JSON=1
json_open() { echo "["; FIRST_JSON=1; }
json_close() { echo "]"; }
json_entry() {
  local service="$1"
  local file="$2"
  local setting="$3"
  local reason="$4"
  local recommendation="$5"

  [[ "$FIRST_JSON" -eq 0 ]] && echo "," || FIRST_JSON=0
  cat <<EOF
{
  "service": "$service",
  "file": "$file",
  "setting": "$setting",
  "reason": "$reason",
  "recommendation": "$recommendation"
}
EOF
}

console_report() {
  local service="$1"
  local file="$2"
  local setting="$3"
  local reason="$4"
  local recommendation="$5"

  echo "[$service] $setting"
  echo "  Reason: $reason"
  echo "  Recommendation: $recommendation"
  echo "  File: $file"
  echo ""
}

#######################################
# Begin audit
#######################################

if [[ -z "$OUTFILE" ]]; then
  echo "=== Mail Server Vulnerability Audit ==="
  echo "This script checks Postfix/Dovecot configs for vulnerability to STARTTLS downgrade."
  echo ""
fi

# JSON output goes to file if -o specified, otherwise console
output_target="${OUTFILE:-/dev/stdout}"

if [[ -n "$OUTFILE" ]]; then
  json_open > "$OUTFILE"
fi

#######################################
# Postfix checks
#######################################
POSTFIX_ISSUES=0
if [[ "$HAS_POSTFIX" -eq 1 ]]; then
  # main.cf
  if [[ -f "$POSTFIX_MAIN" ]]; then
    tls_level=$(postconf -h smtpd_tls_security_level 2>/dev/null || true)
    tls_auth_only=$(postconf -h smtpd_tls_auth_only 2>/dev/null || true)

    if [[ "$tls_level" == "may" ]]; then
      if [[ -n "$OUTFILE" ]]; then
        json_entry "Postfix" "$POSTFIX_MAIN" "smtpd_tls_security_level=may" \
                   "TLS is optional; STARTTLS stripping is possible" \
                   "smtpd_tls_security_level = encrypt" >> "$OUTFILE"
      else
        console_report "Postfix" "$POSTFIX_MAIN" "smtpd_tls_security_level=may" \
                       "TLS is optional; STARTTLS stripping is possible" \
                       "smtpd_tls_security_level = encrypt"
      fi
      POSTFIX_ISSUES=1
    fi

    if [[ "$tls_auth_only" == "no" ]]; then
      if [[ -n "$OUTFILE" ]]; then
        json_entry "Postfix" "$POSTFIX_MAIN" "smtpd_tls_auth_only=no" \
                   "AUTH allowed before TLS negotiation" \
                   "smtpd_tls_auth_only = yes" >> "$OUTFILE"
      else
        console_report "Postfix" "$POSTFIX_MAIN" "smtpd_tls_auth_only=no" \
                       "AUTH allowed before TLS negotiation" \
                       "smtpd_tls_auth_only = yes"
      fi
      POSTFIX_ISSUES=1
    fi
  fi

  # master.cf
  if [[ -f "$POSTFIX_MASTER" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ smtpd_tls_security_level=may ]]; then
        if [[ -n "$OUTFILE" ]]; then
          json_entry "Postfix" "$POSTFIX_MASTER" "$line" \
                     "submission service allows STARTTLS downgrade" \
                     "smtpd_tls_security_level = encrypt" >> "$OUTFILE"
        else
          console_report "Postfix" "$POSTFIX_MASTER" "$line" \
                         "submission service allows STARTTLS downgrade" \
                         "smtpd_tls_security_level = encrypt"
        fi
        POSTFIX_ISSUES=1
      fi
      if [[ "$line" =~ smtpd_tls_auth_only=no ]]; then
        if [[ -n "$OUTFILE" ]]; then
          json_entry "Postfix" "$POSTFIX_MASTER" "$line" \
                     "submission service allows AUTH before TLS" \
                     "smtpd_tls_auth_only = yes" >> "$OUTFILE"
        else
          console_report "Postfix" "$POSTFIX_MASTER" "$line" \
                         "submission service allows AUTH before TLS" \
                         "smtpd_tls_auth_only = yes"
        fi
        POSTFIX_ISSUES=1
      fi
    done < <(grep -A10 "^submission\s" "$POSTFIX_MASTER" 2>/dev/null)
  fi

  # Documentation notes
  if [[ "$POSTFIX_ISSUES" -eq 1 && -z "$OUTFILE" ]]; then
    echo "Postfix config documentation:"
    echo "  main.cf -> man 5 postconf, https://www.postfix.org/postconf.5.html"
    echo "  master.cf -> man 5 master, http://www.postfix.org/master.5.html"
    echo ""
  fi
fi

#######################################
# Dovecot checks
#######################################
DOVECOT_ISSUES=0
dovecot_get() {
  for file in "$DOVECOT_AUTH" "$DOVECOT_SSL" "$DOVECOT_MAIN"; do
    if [[ -f "$file" ]]; then
      val=$(grep -hE "^\s*$1\s*=\s*" "$file" 2>/dev/null | tail -n1 | awk -F= '{print $2}' | tr -d ' ')
      if [[ -n "$val" ]]; then
        echo "$file:$val"
        return 0
      fi
    fi
  done
  return 1
}

if [[ "$HAS_DOVECOT" -eq 1 ]]; then
  # disable_plaintext_auth
  res=$(dovecot_get disable_plaintext_auth || true)
  if [[ -n "$res" ]]; then
    file="${res%%:*}"
    val="${res##*:}"
    if [[ "$val" == "no" ]]; then
      if [[ -n "$OUTFILE" ]]; then
        json_entry "Dovecot" "$file" "disable_plaintext_auth=no" \
                   "Allows cleartext authentication" \
                   "disable_plaintext_auth = yes" >> "$OUTFILE"
      else
        console_report "Dovecot" "$file" "disable_plaintext_auth=no" \
                       "Allows cleartext authentication" \
                       "disable_plaintext_auth = yes"
      fi
      DOVECOT_ISSUES=1
    fi
  fi

  # ssl
  res=$(dovecot_get ssl || true)
  if [[ -n "$res" ]]; then
    file="${res%%:*}"
    val="${res##*:}"
    if [[ "$val" == "yes" ]]; then
      if [[ -n "$OUTFILE" ]]; then
        json_entry "Dovecot" "$file" "ssl=yes" \
                   "TLS is optional; downgrade possible" \
                   "ssl = required" >> "$OUTFILE"
      else
        console_report "Dovecot" "$file" "ssl=yes" \
                       "TLS is optional; downgrade possible" \
                       "ssl = required"
      fi
      DOVECOT_ISSUES=1
    fi
  fi

  # auth_mechanisms
  for file in "$DOVECOT_AUTH" "$DOVECOT_MAIN"; do
    if [[ -f "$file" ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ -n "$OUTFILE" ]]; then
          json_entry "Dovecot" "$file" "$line" \
                     "Plain or LOGIN auth enabled — safe only with mandatory TLS" \
                     "Use mandatory TLS with PLAIN/LOGIN or disable them" >> "$OUTFILE"
        else
          console_report "Dovecot" "$file" "$line" \
                         "Plain or LOGIN auth enabled — safe only with mandatory TLS" \
                         "Use mandatory TLS with PLAIN/LOGIN or disable them"
        fi
        DOVECOT_ISSUES=1
      done < <(grep -hE "^\s*auth_mechanisms.*(plain|login)" "$file" 2>/dev/null)
    fi
  done

  # Documentation note
  if [[ "$DOVECOT_ISSUES" -eq 1 && -z "$OUTFILE" ]]; then
    echo "Dovecot config documentation:"
    echo "  https://doc.dovecot.org/latest/"
    echo ""
  fi
fi

#######################################
# Finish JSON
#######################################
if [[ -n "$OUTFILE" ]]; then
  json_close >> "$OUTFILE"
fi
