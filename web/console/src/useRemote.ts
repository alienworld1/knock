import { useCallback, useEffect, useReducer, useState } from "react";
import { api } from "./api";

type Result<T> = { path: string; data?: T; error?: string };

export function useRemote<T>(
  path: string | null,
  check: (data: unknown) => data is T,
  interval = 0,
) {
  const [result, setResult] = useState<Result<T>>();
  const [revision, refresh] = useReducer((value: number) => value + 1, 0);
  useEffect(() => {
    if (path === null) return;
    const signal = new AbortController();
    let timer: number | undefined;
    async function load(url: string) {
      try {
        const data = await api(url, check, { signal: signal.signal });
        if (!signal.signal.aborted) setResult({ path: url, data });
      } catch (err) {
        if (signal.signal.aborted) return;
        const error =
          err instanceof TypeError
            ? "Couldn't reach the console. Check that knock console is running."
            : err instanceof Error
              ? err.message
              : "Console request failed.";
        setResult((previous) => ({
          path: url,
          data: previous?.path === url ? previous.data : undefined,
          error,
        }));
      }
      if (!signal.signal.aborted && interval)
        timer = window.setTimeout(() => void load(url), interval);
    }
    void load(path);
    return () => {
      signal.abort();
      window.clearTimeout(timer);
    };
  }, [path, check, interval, revision]);
  const retry = useCallback(() => refresh(), []);
  const current = result?.path === path ? result : undefined;
  return {
    data: current?.data,
    error: current?.error,
    loading: path !== null && !current,
    retry,
  };
}
