#!/usr/bin/env bash

# // ----------------------------------------------------------
# // Disable account wizard, popups, first-run UI
# // ----------------------------------------------------------
# user_pref("mail.accountmanager.prompt_for_new_account", false);
# user_pref("mail.shell.checkDefaultClient", false);
# user_pref("mailnews.start_page.enabled", false);
# user_pref("browser.shell.checkDefaultBrowser", false);

set -e
source email-test-env.sh

PROFILE=$(awk -F= '
  $1=="Name" && $2=="testprofile" {found=1}
  found && $1=="Path" {print $2; exit}
' "$REALHOME/.thunderbird/profiles.ini")

if [ -z "$PROFILE" ]; then
    echo "ERROR: Could not find Thunderbird profile named 'testprofile' in $REALHOME/.thunderbird/"
    exit 1
fi

TB_DIR="$REALHOME/.thunderbird/$PROFILE"

echo "[+] Writing user.js to $TB_DIR"
cat > "$TB_DIR/user.js" <<EOF
// ----------------------------------------------------------
// Account Manager: one identity, multiple incoming servers
// ----------------------------------------------------------
user_pref("mail.accountmanager.accounts", "acc_imap_starttls,acc_imap_tls,acc_pop_starttls,acc_pop_tls");
user_pref("mail.accountmanager.defaultaccount", "acc_imap_starttls");

// ----------------------------------------------------------
// Identity used for all accounts
// ----------------------------------------------------------
user_pref("mail.identity.id1.fullName", "Test User");
user_pref("mail.identity.id1.useremail", "$EMAIL_USER");
user_pref("mail.identity.id1.smtpServer", "smtp_tls");

// ----------------------------------------------------------
// ========== IMAP: STARTTLS (port 143) ==========
// ----------------------------------------------------------
user_pref("mail.account.acc_imap_starttls.identities", "id1");
user_pref("mail.account.acc_imap_starttls.server", "imap_starttls");

user_pref("mail.server.imap_starttls.type", "imap");
user_pref("mail.server.imap_starttls.hostname", "$EMAIL_SERVER");
user_pref("mail.server.imap_starttls.port", $IMAP_PORT_STARTTLS);    // 143
user_pref("mail.server.imap_starttls.userName", "$EMAIL_USER");
user_pref("mail.server.imap_starttls.socketType", 2);                 // 2 = STARTTLS
user_pref("mail.server.imap_starttls.authMethod", 3);                 // password-cleartext

// ----------------------------------------------------------
// ========== IMAP: Implicit TLS (port 993) ==========
// ----------------------------------------------------------
user_pref("mail.account.acc_imap_tls.identities", "id1");
user_pref("mail.account.acc_imap_tls.server", "imap_tls");

user_pref("mail.server.imap_tls.type", "imap");
user_pref("mail.server.imap_tls.hostname", "$EMAIL_SERVER");
user_pref("mail.server.imap_tls.port", $IMAP_PORT_TLS);               // 993
user_pref("mail.server.imap_tls.userName", "$EMAIL_USER");
user_pref("mail.server.imap_tls.socketType", 3);                      // 3 = SSL/TLS
user_pref("mail.server.imap_tls.authMethod", 3);

// ----------------------------------------------------------
// ========== POP3: STARTTLS (port 110) ==========
// ----------------------------------------------------------
user_pref("mail.account.acc_pop_starttls.identities", "id1");
user_pref("mail.account.acc_pop_starttls.server", "pop_starttls");

user_pref("mail.server.pop_starttls.type", "pop3");
user_pref("mail.server.pop_starttls.hostname", "$EMAIL_SERVER");
user_pref("mail.server.pop_starttls.port", $POP3_PORT_STARTTLS);      // 110
user_pref("mail.server.pop_starttls.userName", "$EMAIL_USER");
user_pref("mail.server.pop_starttls.socketType", 2);                  // 2 = STARTTLS
user_pref("mail.server.pop_starttls.authMethod", 3);

// ----------------------------------------------------------
// ========== POP3: Implicit TLS (port 995) ==========
// ----------------------------------------------------------
user_pref("mail.account.acc_pop_tls.identities", "id1");
user_pref("mail.account.acc_pop_tls.server", "pop_tls");

user_pref("mail.server.pop_tls.type", "pop3");
user_pref("mail.server.pop_tls.hostname", "$EMAIL_SERVER");
user_pref("mail.server.pop_tls.port", $POP3_PORT_TLS);                // 995
user_pref("mail.server.pop_tls.userName", "$EMAIL_USER");
user_pref("mail.server.pop_tls.socketType", 3);                       // 3 = SSL/TLS
user_pref("mail.server.pop_tls.authMethod", 3);

// =====================================================================
// Outgoing Servers (SMTP)
// =====================================================================

user_pref("mail.smtpservers", "smtp_starttls25,smtp_starttls587,smtp_tls");
user_pref("mail.smtp.defaultserver", "smtp_starttls587");

// ----------------------------------------------------------
// SMTP STARTTLS (port 25)
// ----------------------------------------------------------
user_pref("mail.smtpserver.smtp_starttls25.hostname", "$EMAIL_SERVER");
user_pref("mail.smtpserver.smtp_starttls25.port", $SMTP_PORT_STARTTLS1);      // 25
user_pref("mail.smtpserver.smtp_starttls25.username", "$EMAIL_USER");
user_pref("mail.smtpserver.smtp_starttls25.authMethod", 3);
user_pref("mail.smtpserver.smtp_starttls25.socketType", 2);                   // STARTTLS

// ----------------------------------------------------------
// SMTP STARTTLS (port 587)
// ----------------------------------------------------------
user_pref("mail.smtpserver.smtp_starttls587.hostname", "$EMAIL_SERVER");
user_pref("mail.smtpserver.smtp_starttls587.port", $SMTP_PORT_STARTTLS2);     // 587
user_pref("mail.smtpserver.smtp_starttls587.username", "$EMAIL_USER");
user_pref("mail.smtpserver.smtp_starttls587.authMethod", 3);
user_pref("mail.smtpserver.smtp_starttls587.socketType", 2);                  // STARTTLS

// ----------------------------------------------------------
// SMTP Implicit TLS (port 465)
// ----------------------------------------------------------
user_pref("mail.smtpserver.smtp_tls.hostname", "$EMAIL_SERVER");
user_pref("mail.smtpserver.smtp_tls.port", $SMTP_PORT_TLS);                   // 465
user_pref("mail.smtpserver.smtp_tls.username", "$EMAIL_USER");
user_pref("mail.smtpserver.smtp_tls.authMethod", 3);
user_pref("mail.smtpserver.smtp_tls.socketType", 3);                          // SSL/TLS

// =====================================================================
// Misc settings to avoid interactive prompts
// =====================================================================
user_pref("mail.server.default.autosync_offline_stores", false);
user_pref("mailnews.auto_config.addons", false);
user_pref("mailnews.downloadToTempFile", false);
EOF

