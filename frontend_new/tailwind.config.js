/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0B0F19",
          card: "#111827",
          border: "#1F2937",
          accent: "#38BDF8",
          observed: "#10B981", // Emerald green for verified/observed
          inferred: "#F59E0B", // Amber for statistical inference
          notdet: "#64748B",   // Slate for non-determinable
          critical: "#EF4444",
          high: "#F97316",
          medium: "#EAB308",
          low: "#10B981"
        }
      }
    },
  },
  plugins: [],
}
