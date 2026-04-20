/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  future: {
    hoverOnlyWhenSupported: true,
  },
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
        blink: {
          '0%, 50%':      { opacity: '1' },
          '50.01%, 100%': { opacity: '0' },
        },
      },
      animation: {
        flash: 'flashRow 1s ease-out',
        modalIn: 'modalIn 200ms ease-out',
        blink: 'blink 1s step-end infinite',
      },
    },
  },
  plugins: [],
};
