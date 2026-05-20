import React, {
  type DragEvent,
} from "react";

type Props = {
  file: File | null;
  isDragOver: boolean;
  fileInputRef:
    React.RefObject<HTMLInputElement | null>;

  onClick: () => void;
  onDragOver: (
    e: DragEvent<HTMLDivElement>
  ) => void;
  onDragLeave: () => void;
  onDrop: (
    e: DragEvent<HTMLDivElement>
  ) => void;
  onFileChange: (
    f: File | null
  ) => void;
};

export const FileUpload:
  React.FC<Props> = ({
  file,
  isDragOver,
  fileInputRef,
  onClick,
  onDragOver,
  onDragLeave,
  onDrop,
  onFileChange,
}) => {
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label="Upload OpenAPI file"
      onClick={onClick}
      onKeyDown={(e) => {
        if (
          e.key === "Enter" ||
          e.key === " "
        ) {
          e.preventDefault();
          onClick();
        }
      }}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      className={`
        relative overflow-hidden
        rounded-[28px]
        border border-dashed
        transition-all duration-300
        cursor-pointer
        group
        ${
          isDragOver
            ? `
              border-blue-500
              bg-blue-500/10
              shadow-[0_0_40px_rgba(59,130,246,0.15)]
              scale-[1.01]
            `
            : `
              border-slate-700
              bg-slate-950/70
              hover:border-slate-500
              hover:bg-slate-900/70
            `
        }
      `}
    >
      {/* Glow background */}
      <div
        className="
          pointer-events-none
          absolute inset-0
          bg-[radial-gradient(circle_at_top,rgba(59,130,246,0.08),transparent_55%)]
        "
      />

      <div className="relative z-10 flex min-h-[320px] flex-col items-center justify-center px-8 py-12 text-center">
        {/* Icon */}
        <div
          className={`
            mb-6 flex h-20 w-20
            items-center justify-center
            rounded-3xl
            border
            transition-all duration-300
            ${
              isDragOver
                ? `
                  border-blue-400/40
                  bg-blue-500/15
                  text-blue-400
                `
                : `
                  border-slate-800
                  bg-slate-900
                  text-slate-400
                  group-hover:text-slate-200
                `
            }
          `}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-9 w-9"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.8}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M12 12v9m0 0l-3-3m3 3l3-3"
            />
          </svg>
        </div>

        {/* Title */}
        <h3 className="text-lg font-semibold text-slate-100">
          Upload OpenAPI Specification
        </h3>

        {/* Subtitle */}
        <p className="mt-2 max-w-md text-sm leading-relaxed text-slate-400">
          Drag & drop your Swagger /
          OpenAPI file here or click
          to browse locally.
        </p>

        {/* Supported formats */}
        <div className="mt-3 flex gap-2">
          {[
            ".json",
            ".yaml",
            ".yml",
          ].map((ext) => (
            <span
              key={ext}
              className="
                rounded-full
                border border-slate-800
                bg-slate-900
                px-3 py-1
                text-xs
                text-slate-400
              "
            >
              {ext}
            </span>
          ))}
        </div>

        {/* File state */}
        <div className="mt-8">
          {file ? (
            <div
              className="
                flex items-center gap-3
                rounded-2xl
                border border-emerald-500/20
                bg-emerald-500/10
                px-5 py-3
              "
            >
              <div
                className="
                  flex h-10 w-10
                  items-center justify-center
                  rounded-xl
                  bg-emerald-500/15
                  text-emerald-400
                "
              >
                ✓
              </div>

              <div className="text-left">
                <p className="max-w-[280px] truncate text-sm font-medium text-emerald-300">
                  {file.name}
                </p>

                <p className="text-xs text-emerald-500/80">
                  File ready for
                  analysis
                </p>
              </div>
            </div>
          ) : (
            <div className="text-sm text-slate-500">
              No file selected
            </div>
          )}
        </div>

        {/* CTA */}
        {!file && (
          <button
            type="button"
            className="
              mt-8 rounded-2xl
              bg-blue-600
              px-5 py-3
              text-sm font-medium
              text-white
              shadow-lg shadow-blue-600/20
              transition-all
              hover:bg-blue-500
              hover:shadow-blue-500/30
            "
          >
            Choose File
          </button>
        )}

        <input
          type="file"
          ref={fileInputRef}
          hidden
          accept=".yaml,.yml,.json"
          onChange={(e) =>
            onFileChange(
              e.target.files?.[0] ??
                null
            )
          }
        />
      </div>
    </div>
  );
};