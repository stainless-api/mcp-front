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
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/stainless-api/mcp-front' },
			],
			sidebar: [
				{ label: 'Introduction', slug: 'index' },
				{ label: 'Quickstart', slug: 'quickstart' },
				{ label: 'Configuration', slug: 'configuration' },
				{ label: 'Identity Providers', slug: 'identity-providers' },
				{ label: 'Server Types', slug: 'server-types' },
				{ label: 'Service Authentication', slug: 'service-authentication' },
				{ label: 'API Reference', slug: 'api-reference' },
				{ label: 'Architecture', slug: 'architecture' },
				{ label: 'License', slug: 'license' },
			],
			customCss: ['./src/styles/custom.css'],
			components: {
				ThemeSelect: './src/components/CustomThemeSelect.astro',
			},
		}),
	],
})
