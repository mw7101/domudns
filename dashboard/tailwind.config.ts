import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './lib/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: '#0f172a',
        'surface-2': '#1e293b',
        'surface-3': '#252530',
        border: '#334155',
        muted: '#64748b',
        'muted-2': '#94a3b8',
        text: '#f1f5f9',
        'text-2': '#e2e8f0',
        primary: '#0ea5e9',
        accent: '#6366f1',
      },
      animation: {
        'move-border': 'move-border 4s linear infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        'move-border': {
          '0%, 100%': { 'background-position': '0% 50%' },
          '50%': { 'background-position': '100% 50%' },
        },
        'shimmer': {
          '0%': { 'background-position': '-200% 0' },
          '100%': { 'background-position': '200% 0' },
        },
      },
    },
  },
  plugins: [],
}

export default config
