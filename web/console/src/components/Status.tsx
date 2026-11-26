import { status } from "./classes";
import { CheckCircleIcon } from "@phosphor-icons/react/CheckCircle";
import { ClockIcon } from "@phosphor-icons/react/Clock";
import { LockSimpleIcon } from "@phosphor-icons/react/LockSimple";
import { WarningIcon } from "@phosphor-icons/react/Warning";
import { WarningCircleIcon } from "@phosphor-icons/react/WarningCircle";

export type StatusTone = "success" | "warning" | "danger" | "neutral";

const toneClass: Record<StatusTone, string> = {
  success: " text-success",
  warning: " text-warning",
  danger: " text-danger",
  neutral: " text-muted",
};

export function StatusBadge({
  label,
  tone,
  icon,
  role,
}: {
  label: string;
  tone: StatusTone;
  icon?: "clock" | "alert";
  role?: "status";
}) {
  const Icon =
    tone === "success"
      ? CheckCircleIcon
      : tone === "danger"
        ? WarningIcon
        : tone === "neutral"
          ? LockSimpleIcon
          : icon === "clock"
            ? ClockIcon
            : WarningCircleIcon;
  return (
    <span className={status + toneClass[tone]} role={role}>
      <Icon size={16} aria-hidden />
      {label}
    </span>
  );
}
