(function () {
  function ensureContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
      return container;
    }
    try {
      if (container.parentElement !== document.body) document.body.appendChild(container);
    } catch (e) {}
    return container;
  }

  function iconSvg(kind) {
    if (kind === 'success') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';
    if (kind === 'error') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="M6 6l12 12"/></svg>';
    if (kind === 'warn') return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
  }

  function makeStorageKey(session, name) {
    return `toast:${session}:${name}`;
  }

  function wasShown(session, name) {
    try {
      return window.localStorage.getItem(makeStorageKey(session, name)) === '1';
    } catch (e) {
      return false;
    }
  }

  function markShown(session, name) {
    try {
      window.localStorage.setItem(makeStorageKey(session, name), '1');
    } catch (e) {}
  }

  function showToast(container, opts) {
    const kind = opts.kind || 'info';
    const title = opts.title || '';
    const msg = opts.msg || '';
    const timeoutMs = (typeof opts.timeoutMs === 'number') ? opts.timeoutMs : 12000;

    const el = document.createElement('div');
    el.className = `toast toast-${kind}`;
    el.innerHTML = `
      <div class="toast-icon">${iconSvg(kind)}</div>
      <div class="toast-body">
        <div class="toast-title">${title}</div>
        <div class="toast-msg">${msg}</div>
      </div>
      <button class="toast-close" aria-label="Close" title="Close">×</button>
    `;

    const closeBtn = el.querySelector('.toast-close');
    const dismiss = () => {
      if (el.dataset.closing === '1') return;
      el.dataset.closing = '1';
      el.classList.add('toast-out');
      setTimeout(() => { el.remove(); }, 260);
    };
    if (closeBtn) closeBtn.addEventListener('click', dismiss);

    container.appendChild(el);
    if (timeoutMs > 0) setTimeout(dismiss, timeoutMs);
  }

  async function pollOnce(container, session) {
    const r = await fetch(`/api/session/${encodeURIComponent(session)}`, { cache: 'no-store' });
    const j = await r.json();
    if (!j || !j.ok) return;

    const verdict = (j.verdict || 'INCONCLUSIVE');
    const events = Array.isArray(j.events) ? j.events : [];
    const summary = (j.summary || {});
    const imap = (summary.imap || {});
    const smtp = (summary.smtp || {});

    const hasAny = events.length > 0;
    const hasAuth = events.some(e => ['auth_plain', 'auth_login', 'login_command'].includes(e.event));
    const hasSend = events.some(e => (e.proto === 'smtp' && e.event === 'data_end'));
    const imapTested = ((Number(imap.auth_tls || 0) + Number(imap.auth_plain || 0)) > 0);
    const smtpTested = ((Number(smtp.auth_tls || 0) + Number(smtp.auth_plain || 0)) > 0);

    const mismatch = events.find(e => e.event === 'session_mismatch');
    if (mismatch && !wasShown(session, 'session_mismatch')) {
      const user = mismatch.username || '';
      const usess = mismatch.username_session || '';
      showToast(container, {
        kind: 'warn',
        title: 'Wrong username detected',
        msg: `Your client is still using an old username (${user}). Please switch to the username shown on this page (test-${session}).`,
        timeoutMs: 22000,
      });
      markShown(session, 'session_mismatch');
    }

    if (mismatch) {
      return;
    }

    if (hasAny && !wasShown(session, 'seen_client')) {
      showToast(container, {
        kind: 'info',
        title: 'Client activity detected',
        msg: 'We see your mail client connecting. Continue with login (username/password).',
        timeoutMs: 12000,
      });
      markShown(session, 'seen_client');
    }

    if (hasAuth && !wasShown(session, 'login_attempt')) {
      showToast(container, {
        kind: 'warn',
        title: 'Login attempt detected',
        msg: 'Next step: send a test email (any recipient, any content). Keep the status page open for live updates.',
        timeoutMs: 15000,
      });
      markShown(session, 'login_attempt');
    }

    if (hasSend && !wasShown(session, 'send_attempt')) {
      showToast(container, {
        kind: 'info',
        title: 'Send attempt observed',
        msg: 'We observed an SMTP send attempt. Wait a moment for the client result and check prompts.',
        timeoutMs: 12000,
      });
      markShown(session, 'send_attempt');
    }

    if (verdict === 'FAIL' && (imapTested || smtpTested) && !wasShown(session, 'done_fail')) {
      showToast(container, {
        kind: 'error',
        title: 'FAIL detected',
        msg: 'Plaintext credentials exposure was observed. Do NOT accept insecure downgrade prompts.',
        timeoutMs: 22000,
      });
      markShown(session, 'done_fail');
    }

    if (verdict === 'PASS' && imapTested && smtpTested && !wasShown(session, 'done_pass')) {
      showToast(container, {
        kind: 'success',
        title: 'Test run complete',
        msg: 'IMAP and SMTP were tested; no plaintext credentials observed. You can proceed to the next testcase.',
        timeoutMs: 20000,
      });
      markShown(session, 'done_pass');
    }

    if (verdict === 'WARN' && !wasShown(session, 'done_warn')) {
      showToast(container, {
        kind: 'warn',
        title: 'Client prompt reported',
        msg: 'A downgrade/security prompt was reported in the client UI. Treat this as a warning and do not accept insecure suggestions.',
        timeoutMs: 22000,
      });
      markShown(session, 'done_warn');
    }

    if (verdict === 'NOT_APPLICABLE' && !wasShown(session, 'done_na')) {
      showToast(container, {
        kind: 'info',
        title: 'Client cannot connect reported',
        msg: 'The client could not connect in this step (e.g., insists on implicit TLS ports). Try another client or manual STARTTLS settings.',
        timeoutMs: 22000,
      });
      markShown(session, 'done_na');
    }
  }

  window.initToasts = function initToasts(session, opts) {
    if (!session) return;
    const container = ensureContainer();
    const intervalMs = (opts && typeof opts.intervalMs === 'number') ? opts.intervalMs : 2000;

    const run = async () => {
      try {
        await pollOnce(container, session);
      } catch (e) {
        return;
      }
    };

    run();
    setInterval(run, intervalMs);
  };
})();
