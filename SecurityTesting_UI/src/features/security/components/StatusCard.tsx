import React from "react";

type StatusType =
  | "idle"
  | "running"
  | "done"
  | "error";

type Props = {
  status: StatusType;
  message: string;
};

const STATUS_CONFIG = {
  running: {
    label: "Running Analysis",
    description:
      "AI agents are processing the API specification",
    badge:
      "bg-blue-500/15 text-blue-400 border-blue-500/20",
    glow:
      "shadow-[0_0_30px_rgba(59,130,246,0.08)]",
    icon: (
      <div
        className="
          h-5 w-5 rounded-full
          border-2 border-slate-700
          border-t-blue-400
          animate-spin
        "
      />
    ),
  },

  done: {
    label: "Analysis Completed",
    description:
      "Security test plan generated successfully",
    badge:
      "bg-emerald-500/15 text-emerald-400 border-emerald-500/20",
    glow:
      "shadow-[0_0_30px_rgba(16,185,129,0.08)]",
    icon: (
      <div
        className="
          flex h-10 w-10 items-center
          justify-center rounded-2xl
          bg-emerald-500/15
          text-emerald-400
        "
      >
        ✓
      </div>
    ),
  },

  error: {
    label: "Analysis Failed",
    description:
      "Something went wrong during execution",
    badge:
      "bg-red-500/15 text-red-400 border-red-500/20",
    glow:
      "shadow-[0_0_30px_rgba(239,68,68,0.08)]",
    icon: (
      <div
        className="
          flex h-10 w-10 items-center
          justify-center rounded-2xl
          bg-red-500/15
          text-red-400
        "
      >
        ✕
      </div>
    ),
  },
};

export const StatusCard:
  React.FC<Props> = ({
  status,
  message,
}) => {
  if (status === "idle")
    return null;

  const current =
    STATUS_CONFIG[status];

  return (
    <section
      role="status"
      aria-live="polite"
      className={`
        relative overflow-hidden
        rounded-[28px]
        border border-slate-800
        bg-slate-950/70
        p-6
        backdrop-blur-xl
        transition-all duration-300
        ${current.glow}
      `}
    >
      {/* Background glow */}
      <div
        className="
          pointer-events-none
          absolute inset-0
          bg-[radial-gradient(circle_at_top_right,rgba(255,255,255,0.04),transparent_40%)]
        "
      />

      <div className="relative z-10">
        {/* Header */}
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            {/* Icon */}
            <div className="mt-0.5">
              {current.icon}
            </div>

            {/* Content */}
            <div>
              <div className="mb-1 flex items-center gap-3">
                <h3 className="text-base font-semibold text-slate-100">
                  {current.label}
                </h3>

                <span
                  className={`
                    rounded-full border
                    px-3 py-1
                    text-xs font-medium
                    ${current.badge}
                  `}
                >
                  {status.toUpperCase()}
                </span>
              </div>

              <p className="text-sm text-slate-400">
                {
                  current.description
                }
              </p>
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="my-5 h-px bg-slate-800" />

        {/* Runtime Message */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-slate-500">
            Runtime Log
          </div>

          <div
            className="
              rounded-2xl
              border border-slate-800
              bg-slate-900/70
              p-4
            "
          >
            <p className="text-sm leading-7 text-slate-300">
              {message}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};