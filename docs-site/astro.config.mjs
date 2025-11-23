// @ts-check
import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'

// https://astro.build/config
export default defineConfig({
	site: 'https://stainless-api.github.io',
	base: '/mcp-front',
	integrations: [
		starlight({
			title: '',
			description: 'Auth proxy for MCP servers',
			logo: {
				alt: 'MCP Front Logo',
				light: './src/assets/logo-light.svg',
				dark: './src/assets/logo.svg',
			},
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/dgellow/mcp-front' },
			],
			sidebar: [
				{ label: 'Introduction', slug: 'index' },
				{ label: 'Quickstart', slug: 'quickstart' },
				{
					label: 'Guides',
					items: [
						{ label: 'OAuth with Google', slug: 'examples/oauth-google' },
						{ label: 'Bearer Token', slug: 'examples/bearer-token' },
					],
				},
				{ label: 'Configuration', slug: 'configuration' },
				{ label: 'API Reference', slug: 'api-reference' },
			],
			customCss: ['./src/styles/custom.css'],
			components: {
				Header: './src/components/CustomHeader.astro',
				ThemeSelect: './src/components/CustomThemeSelect.astro',
			},
		}),
	],
})
