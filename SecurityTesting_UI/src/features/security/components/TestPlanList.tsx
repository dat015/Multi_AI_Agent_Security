import React from "react";
import type { TestCase } from "../types";

type Props = {
  testPlan: TestCase[];
  sessionId: string | null;
};

export const TestPlanList:
  React.FC<Props> = ({
  testPlan,
  sessionId,
}) => {
  const handleDownload = () => {
    if (!sessionId) return;

    window.location.href =
      `/api/agent/download/${sessionId}`;
  };

  return (
    <section className="mt-8">
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-slate-100">
            Security Test Plan
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            Generated attack scenarios
            based on detected API risks
          </p>
        </div>

        {testPlan.length > 0 && (
          <div className="rounded-2xl border border-slate-800 bg-slate-900 px-4 py-2 text-sm text-slate-300">
            {testPlan.length} findings
          </div>
        )}
      </div>

      {/* Empty state */}
      {testPlan.length === 0 ? (
        <div
          className="
            flex min-h-[220px]
            flex-col items-center
            justify-center
            rounded-[28px]
            border border-slate-800
            bg-slate-950/60
            text-center
          "
        >
          <div className="mb-4 text-5xl">
            🔍
          </div>

          <h3 className="text-lg font-semibold text-slate-200">
            No Test Cases Generated
          </h3>

          <p className="mt-2 max-w-md text-sm text-slate-500">
            The system could not
            generate security test
            cases for the uploaded
            specification.
          </p>
        </div>
      ) : (
        <div className="grid gap-5">
          {testPlan.map(
            (item, index) => (
              <article
                key={`${item.endpoint}-${index}`}
                className="
                  group relative overflow-hidden
                  rounded-[28px]
                  border border-slate-800
                  bg-slate-950/70
                  p-6
                  backdrop-blur-xl
                  transition-all duration-300
                  hover:border-slate-700
                  hover:bg-slate-900/80
                  hover:shadow-[0_0_30px_rgba(59,130,246,0.06)]
                "
              >
                {/* Glow */}
                <div
                  className="
                    pointer-events-none
                    absolute inset-0
                    bg-[radial-gradient(circle_at_top_right,rgba(59,130,246,0.05),transparent_40%)]
                  "
                />

                <div className="relative z-10">
                  {/* Header */}
                  <div className="mb-5 flex items-start justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="mb-3 flex flex-wrap items-center gap-3">
                        {/* Method */}
                        <span
                          className="
                            rounded-xl
                            border border-blue-500/20
                            bg-blue-500/10
                            px-3 py-1
                            text-xs font-semibold
                            tracking-wide
                            text-blue-400
                          "
                        >
                          {item.method}
                        </span>

                        {/* Vuln type */}
                        <span
                          className="
                            rounded-xl
                            border border-amber-500/20
                            bg-amber-500/10
                            px-3 py-1
                            text-xs font-medium
                            text-amber-400
                          "
                        >
                          {
                            item.vuln_type
                          }
                        </span>
                      </div>

                      {/* Endpoint */}
                      <h3
                        className="
                          truncate
                          font-mono
                          text-base
                          text-slate-100
                        "
                      >
                        {item.endpoint}
                      </h3>
                    </div>

                    {/* Finding number */}
                    <div
                      className="
                        flex h-10 w-10
                        shrink-0
                        items-center justify-center
                        rounded-2xl
                        border border-slate-800
                        bg-slate-900
                        text-sm
                        font-medium
                        text-slate-400
                      "
                    >
                      #
                      {index + 1}
                    </div>
                  </div>

                  {/* Divider */}
                  <div className="mb-5 h-px bg-slate-800" />

                  {/* Test steps */}
                  <div className="space-y-3">
                    <div className="mb-3 text-xs font-medium uppercase tracking-widest text-slate-500">
                      Attack Steps
                    </div>

                    {item.test_steps
                      ?.length ? (
                      item.test_steps.map(
                        (
                          step,
                          i
                        ) => (
                          <div
                            key={i}
                            className="
                              rounded-2xl
                              border border-slate-800
                              bg-slate-900/70
                              p-4
                              transition-all
                              hover:border-slate-700
                            "
                          >
                            <div className="mb-2 flex items-center gap-3">
                              <div
                                className="
                                  flex h-7 w-7
                                  items-center justify-center
                                  rounded-full
                                  bg-blue-500/10
                                  text-xs
                                  font-semibold
                                  text-blue-400
                                "
                              >
                                {step.step ??
                                  i +
                                    1}
                              </div>

                              <span className="text-sm font-medium text-slate-200">
                                Step{" "}
                                {step.step ??
                                  i +
                                    1}
                              </span>
                            </div>

                            <p className="text-sm leading-7 text-slate-300">
                              {
                                step.description
                              }
                            </p>

                            {step.expected_indicator && (
                              <div
                                className="
                                  mt-4 rounded-xl
                                  border border-emerald-500/15
                                  bg-emerald-500/10
                                  p-3
                                "
                              >
                                <div className="mb-1 text-xs font-medium uppercase tracking-wide text-emerald-400">
                                  Expected Indicator
                                </div>

                                <p className="text-sm text-emerald-300">
                                  {
                                    step.expected_indicator
                                  }
                                </p>
                              </div>
                            )}
                          </div>
                        )
                      )
                    ) : (
                      <div className="text-sm text-slate-500">
                        No steps
                        available
                      </div>
                    )}
                  </div>
                </div>
              </article>
            )
          )}
        </div>
      )}

      {/* Download */}
      {sessionId && (
        <div className="mt-8 flex justify-end">
          <button
            onClick={handleDownload}
            className="
              flex items-center gap-2
              rounded-2xl
              border border-blue-500/20
              bg-blue-500/10
              px-5 py-3
              text-sm font-medium
              text-blue-400
              transition-all duration-200
              hover:bg-blue-500/20
              hover:text-blue-300
              hover:shadow-lg
              hover:shadow-blue-500/10
            "
          >
            ⬇ Download
            test_plan.json
          </button>
        </div>
      )}
    </section>
  );
};