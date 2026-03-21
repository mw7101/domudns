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
        surface:    '#0A0A0C',
        'surface-2':'#111116',
        'surface-3':'#1C1C23',
        border:     '#2A2A34',
        muted:      '#5A5A6E',
        'muted-2':  '#9A9AAE',
        text:       '#F4F4EF',
        'text-2':   '#CCCCC0',
        primary:    '#F59E0B',
        accent:     '#D97706',
        neon:       '#FCD34D',
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
