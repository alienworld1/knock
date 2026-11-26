import { useEffect, useState } from "react";
import { clock } from "./format";
export function useClock() {
  const [now, setNow] = useState(clock);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(clock()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}
