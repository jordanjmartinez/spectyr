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
      },
      animation: {
        flash: 'flashRow 1s ease-out',
      },
    },
  },
  plugins: [],
};
