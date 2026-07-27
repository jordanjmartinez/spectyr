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
      // Visual pass VG: the named design tokens (the one visual language;
      // values documented in src/components/ui.jsx). New and polished code
      // uses these names; legacy arbitrary values carry the same colors.
      colors: {
        ink: { DEFAULT: '#101218', hover: '#1e2330' },
        body: '#1a2332',
        dim: '#57606a',
        muted: '#6e7781',
        faint: '#8b949e',
        edge: '#e2e6ea',
        ctrl: '#d0d7de',
        seam: '#eef1f4',
        canvas: '#f6f8fa',
        accent: '#16436b',
        ok: '#6fa868',
        warn: '#c08a3e',
        danger: '#b45858',
      },
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
