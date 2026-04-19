/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', 'sans-serif'],
      },
      keyframes: {
        flashRow: {
          '0%': { backgroundColor: 'rgba(255, 255, 255, 0.1)' },
          '100%': { backgroundColor: 'transparent' },
        },
        modalIn: {
          '0%':   { opacity: '0', transform: 'scale(0.98)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
      },
      animation: {
        flash: 'flashRow 1s ease-out',
        modalIn: 'modalIn 200ms ease-out',
      },
    },
  },
  plugins: [],
};
