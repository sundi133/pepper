"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function AssessmentReportDocument({ markdown }: { markdown: string }) {
  return (
    <article
      className="assessment-report-document mx-auto max-w-4xl px-4 py-10 text-[15px] leading-relaxed text-stone-900"
      style={{ fontFamily: "var(--pentest-serif), ui-serif, Georgia, serif" }}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children, ...props }) => (
            <h1
              className="mt-10 scroll-mt-24 border-b border-stone-200 pb-2 text-2xl font-bold tracking-tight text-stone-950 first:mt-0"
              {...props}
            >
              {children}
            </h1>
          ),
          h2: ({ children, ...props }) => (
            <h2
              className="mt-8 scroll-mt-24 text-xl font-semibold text-stone-900"
              {...props}
            >
              {children}
            </h2>
          ),
          h3: ({ children, ...props }) => (
            <h3 className="mt-6 text-lg font-semibold text-stone-800" {...props}>
              {children}
            </h3>
          ),
          p: ({ children, ...props }) => (
            <p className="my-3 text-stone-800" {...props}>
              {children}
            </p>
          ),
          ul: ({ children, ...props }) => (
            <ul className="my-3 list-disc space-y-1 pl-6 text-stone-800" {...props}>
              {children}
            </ul>
          ),
          ol: ({ children, ...props }) => (
            <ol className="my-3 list-decimal space-y-1 pl-6 text-stone-800" {...props}>
              {children}
            </ol>
          ),
          li: ({ children, ...props }) => (
            <li className="leading-relaxed" {...props}>
              {children}
            </li>
          ),
          table: ({ children, ...props }) => (
            <div className="my-4 max-w-full overflow-x-auto rounded-md border border-stone-200">
              <table className="w-full min-w-[32rem] border-collapse text-sm" {...props}>
                {children}
              </table>
            </div>
          ),
          thead: ({ children, ...props }) => (
            <thead className="bg-stone-100" {...props}>
              {children}
            </thead>
          ),
          th: ({ children, ...props }) => (
            <th
              className="border border-stone-200 px-3 py-2 text-left font-semibold text-stone-900"
              {...props}
            >
              {children}
            </th>
          ),
          td: ({ children, ...props }) => (
            <td className="border border-stone-200 px-3 py-2 align-top text-stone-800" {...props}>
              {children}
            </td>
          ),
          code: ({ className, children, ...props }) => {
            const isBlock = /language-/.test(className || "");
            if (isBlock) {
              return (
                <code
                  className={`block whitespace-pre text-[13px] leading-relaxed text-stone-100 ${className || ""}`}
                  style={{
                    fontFamily: "var(--pentest-mono), ui-monospace, monospace",
                  }}
                  {...props}
                >
                  {children}
                </code>
              );
            }
            return (
              <code
                className="rounded bg-stone-100 px-1.5 py-0.5 text-[0.9em] text-stone-900"
                style={{
                  fontFamily: "var(--pentest-mono), ui-monospace, monospace",
                }}
                {...props}
              >
                {children}
              </code>
            );
          },
          pre: ({ children, ...props }) => (
            <pre
              className="my-4 max-w-full overflow-x-auto rounded-md bg-stone-950 p-4"
              {...props}
            >
              {children}
            </pre>
          ),
          blockquote: ({ children, ...props }) => (
            <blockquote
              className="my-4 border-l-4 border-amber-400 bg-amber-50/50 py-1 pl-4 text-stone-800"
              {...props}
            >
              {children}
            </blockquote>
          ),
          hr: () => <hr className="my-8 border-stone-200" />,
          strong: ({ children, ...props }) => (
            <strong className="font-semibold text-stone-950" {...props}>
              {children}
            </strong>
          ),
          a: ({ children, ...props }) => (
            <a className="text-indigo-700 underline underline-offset-2 hover:text-indigo-900" {...props}>
              {children}
            </a>
          ),
        }}
      >
        {markdown}
      </ReactMarkdown>
    </article>
  );
}
