export function Mark() {
  return (
    <div className="flex items-center gap-2 px-2 text-brass [&>span]:text-2xl/8 [&>span]:font-semibold [&>span]:tracking-tight [&>span]:text-ink">
      <svg
        viewBox="0 0 24 24"
        width="26"
        height="26"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        aria-hidden="true"
      >
        <path d="M2.5 21.5h19m-17-0.5v-17h13v17M8 21.5v-16l7-2v18" />
        <circle cx="12.5" cy="13" r="0.9" fill="currentColor" stroke="none" />
      </svg>
      <span>knock</span>
    </div>
  );
}
