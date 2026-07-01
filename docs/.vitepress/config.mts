import { defineConfig } from 'vitepress'
import llmstxt from 'vitepress-plugin-llms'

// https://vitepress.dev/reference/site-config
export default defineConfig({
  title: 'Lukk',
  description: 'Minimal-dependency JWT authentication for first-party Laravel applications — short-lived access tokens, rotating refresh tokens with reuse detection, and instant revocation.',
  base: '/lukk/',
  lastUpdated: true,
  // Docs use manual <a name="…"> anchors (GitHub-style), not heading ids, so skip the
  // build-time dead-link checker (the anchors still resolve at runtime).
  ignoreDeadLinks: true,
  head: [
    ['meta', { name: 'theme-color', content: '#3c8772' }],
  ],
  // Emit llms.txt + llms-full.txt (+ per-page .md) so AI tools can ingest the docs.
  // https://llmstxt.org
  vite: {
    plugins: [llmstxt()],
  },
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/introduction' },
      { text: 'Config', link: '/configuration' },
      { text: 'Customization', link: '/customization' },
      { text: 'Reference', link: '/architecture' },
    ],
    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Introduction', link: '/introduction' },
          { text: 'Installation', link: '/installation' },
          { text: 'Configuration', link: '/configuration' },
        ],
      },
      {
        text: 'Core',
        items: [
          { text: 'Authentication', link: '/authentication' },
          { text: 'Customization', link: '/customization' },
          { text: 'Events & Maintenance', link: '/events' },
        ],
      },
      {
        text: 'Additional Features',
        items: [
          { text: 'Two-Factor Authentication', link: '/two-factor-authentication' },
          { text: 'Passkeys', link: '/passkeys' },
          { text: 'Confirmation', link: '/confirmation' },
        ],
      },
      {
        text: 'Reference',
        items: [
          { text: 'Deployment', link: '/deployment' },
          { text: 'Architecture & Security', link: '/architecture' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/stsepelin/lukk' },
    ],
    search: { provider: 'local' },
    editLink: {
      pattern: 'https://github.com/stsepelin/lukk/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Unofficial, independent package — not affiliated with or endorsed by Laravel.',
    },
  },
})
