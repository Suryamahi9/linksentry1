import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: "#0A0E14",
          lighter: "#12161E",
          border: "#1E2330",
        },
        phosphor: {
          DEFAULT: "#4FE8C4",
          dim: "#2A8A72",
          glow: "#4FE8C440",
        },
        amber: {
          DEFAULT: "#F5A623",
          dim: "#8B6013",
        },
        danger: {
          DEFAULT: "#E4573D",
          dim: "#7A2E20",
        },
      },
      fontFamily: {
        sans: ["Space Grotesk", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "scan-line": "scan-line 2s ease-in-out infinite",
      },
      keyframes: {
        "scan-line": {
          "0%, 100%": { transform: "translateX(-100%)" },
          "50%": { transform: "translateX(100%)" },
        },
      },
    },
  },
  plugins: [],
};
export default config;
