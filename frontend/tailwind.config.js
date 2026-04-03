/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0f0f1a',
        card: '#1a1a2e',
        gold: '#f5a623',
        teal: '#00b4d8',
        critical: '#ef4444',
        medium: '#f59e0b',
        low: '#10b981',
        text: '#e8e8e8',
      },
    },
  },
  plugins: [],
}
