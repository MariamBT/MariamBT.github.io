/* Recovery credentials stay in memory, never localStorage or query strings. */
(() => {
  'use strict';
  const base = 'https://svjpnvgiqlszprxjchbt.supabase.co/auth/v1';
  const key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN2anBudmdpcWxzenByeGpjaGJ0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODIzNjcwNTgsImV4cCI6MjA5Nzk0MzA1OH0.IL8EbNZMPqnBZ8xfn-7karxBuA5Pmo2vwB9PixFsFwY';
  const form = document.getElementById('reset-form');
  const button = document.getElementById('save-button');
  const status = document.getElementById('status');
  const heading = document.getElementById('heading');
  const password = document.getElementById('password');
  const confirm = document.getElementById('confirm');
  let hash = new URLSearchParams(location.hash.slice(1)).get('token_hash');
  history.replaceState(null, '', location.pathname);
  let session = null;
  let busy = false;
  let done = false;
  const valid = typeof hash === 'string' && /^[a-zA-Z0-9_-]{20,256}$/.test(hash);
  if (!valid) {
    hash = null;
    form.hidden = true;
    status.textContent = 'Open the newest password-reset email to use this page. If needed, request another email in Knotz.';
    return;
  }
  button.disabled = false;
  status.textContent = 'Choose a new password below. Your link will be verified when you save.';
  async function request(path, method, body, token) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
      const response = await fetch(base + path, {
        method, signal: controller.signal, cache: 'no-store',
        credentials: 'omit', referrerPolicy: 'no-referrer',
        headers: { apikey: key, 'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body),
      });
      const data = response.status === 204 ? {} : await response.json();
      if (!response.ok) {
        const error = new Error('Request failed');
        error.status = response.status;
        error.code = data.code || data.error_code;
        throw error;
      }
      return data;
    } finally { clearTimeout(timer); }
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || done) return;
    if (password.value.length < 8 || password.value !== confirm.value) {
      status.textContent = 'Use at least 8 characters and make both passwords match.';
      return;
    }
    busy = true;
    button.disabled = true;
    status.textContent = 'Verifying your link and saving your password…';
    let stage = 'verify';
    try {
      if (!session) {
        // Explicit user action consumes the one-use link, not email previews.
        const result = await request('/verify', 'POST', { token_hash: hash, type: 'recovery' });
        if (!result.access_token || !result.user?.id) throw new Error('Missing verified session');
        session = { access_token: result.access_token, userId: result.user.id };
        hash = null;
      }
      stage = 'save';
      const user = await request('/user', 'PUT', { password: password.value }, session.access_token);
      if (user.id !== session.userId) throw new Error('Unexpected account');
      done = true;
      password.value = '';
      confirm.value = '';
      form.hidden = true;
      heading.textContent = 'Password updated';
      status.textContent = 'Your new password is saved. Return to Knotz and log in with your email and new password.';
      // Best-effort cleanup of this recovery session only; not other devices.
      request('/logout?scope=local', 'POST', {}, session.access_token).catch(() => {});
      session = null;
    } catch (error) {
      if (error.code === 'otp_expired' || (stage === 'verify' && [400, 401, 403, 422].includes(error.status))) {
        hash = null;
        status.textContent = 'This reset link is invalid or expired. Request a new email in Knotz and open its newest link.';
      } else if (error.code === 'same_password') {
        status.textContent = 'Choose a password different from your current password.';
      } else if (stage === 'save' && [400, 422].includes(error.status)) {
        status.textContent = 'That password was not accepted. Try a longer, stronger password.';
      } else if (stage === 'save' && [401, 403].includes(error.status)) {
        session = null;
        status.textContent = 'Your reset session expired. Request a new email in Knotz.';
      } else if (error.status === 429) {
        status.textContent = 'Too many attempts. Wait a few minutes before trying again.';
      } else {
        status.textContent = stage === 'save'
          ? 'We could not confirm whether the password saved. Try logging in with your new password, or retry here.'
          : 'We could not verify the link. Check your connection and retry. If it then says expired, request a new email in Knotz.';
      }
    } finally {
      busy = false;
      button.disabled = done || (!hash && !session);
    }
  });
  window.addEventListener('pagehide', () => { hash = null; session = null; password.value = ''; confirm.value = ''; });
})();
