import { useEffect, useState } from "react";
type Theme = "dark" | "light" | "system";
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const value = localStorage.getItem("knock.theme");
      if (value === "light" || value === "system") return value;
    } catch {
      // Theme storage is optional.
    }
    return "dark";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("knock.theme", theme);
    } catch {
      // Theme still works for this tab.
    }
  }, [theme]);
  return [theme, setTheme] as const;
}
