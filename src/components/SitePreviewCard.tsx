"use client";

import { useState } from "react";
import type { PagePreview, ScanResult } from "@/lib/api";

function hashHue(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return ((h >>> 0) % 360) / 360;
}

const PALETTE = [
  "bg-phosphor/20 text-phosphor border-phosphor/40",
  "bg-amber/20 text-amber border-amber/40",
  "bg-danger/20 text-danger border-danger/40",
  "bg-sky-400/20 text-sky-300 border-sky-400/40",
];

function ScreenshotImage({ url }: { url: string }) {
  const [stage, setStage] = useState(0);
  // Fallback chain: WordPress mshots -> thum.io -> s-shot -> placeholder
  const sources = [
    `https://s.wordpress.com/mshots/v1/${encodeURIComponent(url)}?w=600`,
    `https://image.thum.io/get/width/600/crop/400/${url}`,
    `https://mini.s-shot.ru/600x400/JPEG/600/?${encodeURIComponent(url)}`,
  ];

  if (stage >= sources.length) {
    return (
      <div className="w-full h-[280px] bg-ink flex items-center justify-center">
        <span className="font-mono text-xs text-gray-600">Preview unavailable</span>
      </div>
    );
  }

  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src={sources[stage]}
      alt={`Preview of ${url}`}
      className="w-full h-auto object-cover"
      loading="lazy"
      onError={() => setStage((s) => s + 1)}
    />
  );
}

export function SitePreviewCard({
  result,
}: {
  result: ScanResult;
}) {
  const preview: PagePreview | undefined | null = result.pagePreview;

  return (
    <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden">
      <div className="px-4 py-2 hairline-border-bottom flex items-center justify-between">
        <span className="font-mono text-xs text-gray-500 uppercase tracking-wider">
          Site Preview
        </span>
        <span
          className={`font-mono text-[10px] px-1.5 py-0.5 rounded-sm ${
            preview?.https
              ? "bg-phosphor/10 text-phosphor"
              : "bg-amber/10 text-amber"
          }`}
        >
          {preview?.https ? "HTTPS" : "NO HTTPS"}
        </span>
      </div>

      {/* Screenshot — real visual preview of every website */}
      <div className="bg-ink hairline-border-bottom overflow-hidden">
        <ScreenshotImage url={result.finalUrl} />
      </div>

      {preview ? (
        <div className="p-4 flex gap-4 items-start">
          <div
            className={`w-11 h-11 shrink-0 rounded-sm border flex items-center justify-center font-mono text-lg font-semibold ${
              PALETTE[Math.floor(hashHue(preview.domain) * PALETTE.length)]
            }`}
          >
            {(preview.siteName || preview.domain || "?").charAt(0).toUpperCase()}
          </div>

          <div className="min-w-0 flex-1 space-y-1">
            <div className="font-mono text-sm font-semibold text-white truncate">
              {preview.title}
            </div>
            <div className="font-mono text-[11px] text-phosphor/70 truncate">
              {preview.siteName || preview.domain}
            </div>
            {preview.description && (
              <p className="font-mono text-xs text-gray-500 leading-relaxed line-clamp-2">
                {preview.description}
              </p>
            )}
            <div className="font-mono text-[10px] text-gray-600 truncate pt-1">
              {result.finalUrl}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 flex gap-4 items-start">
          <div
            className={`w-11 h-11 shrink-0 rounded-sm border flex items-center justify-center font-mono text-lg font-semibold ${
              PALETTE[Math.floor(hashHue(result.finalUrl) * PALETTE.length)]
            }`}
          >
            {new URL(result.finalUrl).hostname.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1 space-y-1">
            <div className="font-mono text-sm font-semibold text-white truncate">
              {new URL(result.finalUrl).hostname}
            </div>
            <div className="font-mono text-[10px] text-gray-600 truncate pt-1">
              {result.finalUrl}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}