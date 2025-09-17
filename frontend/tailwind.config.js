/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          primary: '#2563eb',
          danger: '#dc2626',
          warning: '#d97706',
          success: '#059669',
          dark: '#1f2937'
        }
      }
    },
  },
  plugins: [],
}