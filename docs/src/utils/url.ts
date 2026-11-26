export function withBase(path: string): string {
  const base = import.meta.env.BASE_URL.replace(/\/+$/, "");
  const clean = path.replace(/^\/+/, "");
  if (!clean) {
    return `${base}/`;
  }
  return `${base}/${clean}`;
}
