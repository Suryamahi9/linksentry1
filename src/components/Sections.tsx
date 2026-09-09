"use client";

export function PipelineSection() {
  const steps = [
    {
      n: "01",
      title: "Fetch",
      desc: "Resolve and fetch the final URL under strict SSRF guards — private IPs blocked, max 5 redirects, 5s cap.",
    },
    {
      n: "02",
      title: "Analyze",
      desc: "Run the heuristic modules: homoglyphs, IP literals, domain age, certificate trust, redirect chains.",
    },
    {
      n: "03",
      title: "Cross-check",
      desc: "Aggregate threat-intel providers (Safe Browsing, VirusTotal, PhishTank, URLhaus) and community reports.",
    },
    {
      n: "04",
      title: "Score",
      desc: "Combine weighted signals into a 0–100 risk score, mapped to a plain-language verdict.",
    },
  ];

  return (
    <section className="my-24" id="pipeline">
      <div className="flex items-baseline gap-3 mb-8">
        <span className="font-mono text-xs text-phosphor/60">01</span>
        <h2 className="text-xl font-semibold">The scan pipeline</h2>
        <div className="flex-1 hairline-border-top" />
      </div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden">
        {steps.map((s) => (
          <div key={s.n} className="bg-ink-lighter p-5">
            <div className="font-mono text-phosphor text-xs mb-3">{s.n}</div>
            <h3 className="font-sans font-medium text-white mb-2">{s.title}</h3>
            <p className="font-mono text-xs text-gray-500 leading-relaxed">{s.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export function SignalsSection() {
  const signals = [
    { name: "homoglyph-check", on: true, w: "confidence-high", desc: "Unicode lookalikes and punycode spoofing of known brands." },
    { name: "ip-literal", on: true, w: "confidence-high", desc: "Raw IP addresses instead of domain names — a phishing hallmark." },
    { name: "url-shortener", on: true, w: "confidence-mid", desc: "bit.ly, tinyurl, t.co and friends; the resolved target is what gets scored." },
    { name: "domain-age", on: true, w: "confidence-mid", desc: "RDAP lookup flags domains registered in the last 30–90 days." },
    { name: "ssl-check", on: true, w: "confidence-high", desc: "Self-signed, expired, or mismatched certificates." },
    { name: "redirect-chain", on: true, w: "confidence-mid", desc: "Cross-domain redirects that hide the real destination." },
    { name: "dns-resolution", on: true, w: "confidence-high", desc: "Non-resolving domains — dead sites or misspellings." },
  ];

  return (
    <section className="my-24" id="signals">
      <div className="flex items-baseline gap-3 mb-8">
        <span className="font-mono text-xs text-phosphor/60">02</span>
        <h2 className="text-xl font-semibold">Every URL is inspected</h2>
        <div className="flex-1 hairline-border-top" />
      </div>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden">
        {signals.map((s) => (
          <div key={s.name} className="bg-ink-lighter p-5">
            <div className="flex items-center gap-2 mb-2">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  s.w === "confidence-high" ? "bg-phosphor" : "bg-amber"
                }`}
              />
              <span className="font-mono text-xs text-phosphor">{s.name}</span>
            </div>
            <p className="font-mono text-xs text-gray-500 leading-relaxed">{s.desc}</p>
          </div>
        ))}
        <div className="bg-ink-lighter p-5 flex items-center justify-center">
          <span className="font-mono text-xs text-gray-600">
            + threat-intel &amp; community blocklists
          </span>
        </div>
      </div>
    </section>
  );
}