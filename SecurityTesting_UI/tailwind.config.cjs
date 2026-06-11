/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      keyframes: {
        progress: {
          '0%': { width: '0%', left: '0%' },
          '50%': { width: '40%', left: '30%' },
          '100%': { width: '0%', left: '100%' },
        }
      },
      animation: {
        progress: 'progress 2s infinite ease-in-out',
      }
    },
  },
  plugins: [],
};
