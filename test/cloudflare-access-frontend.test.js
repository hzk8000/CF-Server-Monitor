import assert from 'node:assert/strict';
import test from 'node:test';
import { createSSRApp } from 'vue';
import { renderToString } from 'vue/server-renderer';
import { createServer } from 'vite';
import en from '../src/frontend/locales/en.js';

test('Access settings show the identity and hide local authentication controls', async () => {
  const originalWindow = globalThis.window;
  const originalDocument = globalThis.document;
  globalThis.window = {
    addEventListener() {}, removeEventListener() {},
    location: { origin: 'https://monitor.example.com' }
  };
  globalThis.document = { addEventListener() {}, removeEventListener() {} };
  const vite = await createServer({
    appType: 'custom', logLevel: 'silent', server: { middlewareMode: true }
  });
  try {
    const { default: SettingsPanel } = await vite.ssrLoadModule('/src/frontend/views/admin/components/SettingsPanel.vue');
    const props = {
      trans: en, passwordVisible: {}, servers: [],
      currentOrigin: 'https://monitor.example.com',
      selectedApiBase: 'https://monitor.example.com'
    };
    for (const mode of ['password', 'cloudflare-access']) {
      const app = createSSRApp(SettingsPanel, {
        ...props,
        settings: {
          auth_mode: mode, access_email: 'owner@example.com',
          username: 'admin', password_configured: true,
          ua: 'cfsm', notification_timezone: 'Asia/Shanghai', theme_options: '{}'
        }
      });
      const html = await renderToString(app);
      for (const input of ['settings_admin_user', 'jwt_secret', 'turnstile_secret_key']) {
        assert.equal(html.includes(`name="${input}"`), mode === 'password', input);
      }
      if (mode === 'cloudflare-access') {
        assert.ok(html.includes(en.accessLoginManaged));
        assert.ok(html.includes('owner@example.com'));
        assert.match(html, /<input[^>]*id="cfg_is_public"[^>]*disabled/);
        assert.ok(!html.includes('name="settings_admin_passphrase"'));
      }
    }
  } finally {
    await vite.close();
    globalThis.window = originalWindow;
    globalThis.document = originalDocument;
  }
});
