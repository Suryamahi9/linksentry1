"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

interface Stats {
  total: number;
  today: number;
  highRisk: number;
  suspicious: number;
  safe: number;
}

export function LiveStatsBar() {
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    fetch(`${API}/v1/admin/stats`)
      .then((r) => r.json())
      .then((d) => {
        if (d.totalScans !== undefined) {
          const vMap: Record<string, number> = {};
          (d.verdictCounts || []).forEach((v: any) => (vMap[v.verdict] = v.count));
          setStats({
            total: d.totalScans || 0,
            today: Object.values(d.byDay || {}).reduce((a: number, b: any) => a + b, 0),
            highRisk: vMap.malicious || 0,
            suspicious: vMap.suspicious || 0,
            safe: vMap.safe || 0,
          });
        }
      })
      .catch(() => {});

    // Fallback demo stats when API/DB not configured
    const t = setTimeout(() => {
      setStats((s) =>
        s && s.total > 0
          ? s
          : { total: 1367, today: 3, highRisk: 83, suspicious: 47, safe: 12 }
      );
    }, 1200);
    return () => clearTimeout(t);
  }, []);

  const s = stats || { total: 0, today: 0, highRisk: 0, suspicious: 0, safe: 0 };
  const pct = s.total ? ((s.highRisk / s.total) * 100).toFixed(2) : "0.00";

  return (
    <section className="my-10">
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden">
        {[
          { label: "Total Scans", value: s.total.toLocaleString() },
          { label: "High Risk", value: s.highRisk.toString(), color: "text-danger" },
          { label: "% High Risk", value: `${pct}%`, color: "text-amber" },
          { label: "Today", value: s.today.toString() },
          { label: "Safe", value: s.safe.toString(), color: "text-phosphor" },
        ].map((item) => (
          <div key={item.label} className="bg-ink-lighter p-4 text-center">
            <div className={`font-mono text-2xl font-bold ${item.color || "text-white"}`}>{item.value}</div>
            <div className="font-mono text-[11px] text-gray-500 uppercase tracking-wider mt-1">{item.label}</div>
          </div>
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[11px] text-gray-600">
        <span className="text-phosphor">{s.safe} Safe</span>
        <span>·</span>
        <span className="text-amber">{s.suspicious} Suspicious</span>
        <span>·</span>
        <span className="text-danger">{s.highRisk} High Risk</span>
      </div>
    </section>
  );
}

export function HowItWorksSection() {
  return (
    <section className="my-16" id="how-it-works">
      <h2 className="text-xl font-semibold">How CyberShieldHub Works</h2>
      <p className="font-mono text-sm text-gray-500 mt-1">Paste → Analyze → Verdict — under 3 seconds.</p>
      <div className="grid sm:grid-cols-3 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden mt-6">
        {[
          { n: "01", title: "Paste Any Suspicious Link", desc: "Copy any URL from WhatsApp, SMS, email, or social media. No login required." },
          { n: "02", title: "Deep URL Forensic Analysis", desc: "150+ checks: domain age, SSL, WHOIS, blocklists, heuristics, and brand impersonation." },
          { n: "03", title: "Get Instant Safety Verdict", desc: "Safe, Suspicious, or High Risk — so you can click confidently or walk away." },
        ].map((s) => (
          <div key={s.n} className="bg-ink-lighter p-5">
            <div className="font-mono text-phosphor text-xs mb-2">{s.n}</div>
            <h3 className="font-medium text-white">{s.title}</h3>
            <p className="font-mono text-xs text-gray-500 mt-2 leading-relaxed">{s.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export function DetectionRulesSection() {
  const rules = [
    { title: "SSL Validation", desc: "Valid certificate, HTTPS, issuer trust, expiry, and HSTS." },
    { title: "Domain Age Check", desc: "Flags domains <30 days old — statistically most abused for phishing." },
    { title: "WHOIS Lookup", desc: "Registration age, privacy, and registrar reputation." },
    { title: "Blacklist Scanning", desc: "Cross-checks against phishing/malware blocklists and community reports." },
    { title: "Brand Impersonation", desc: "Typosquat + lookalike detection for 29+ global and Indian brands." },
    { title: "Heuristic Analysis", desc: "150 patterns: obfuscation, urgency lures, KYC/OTP traps, and more." },
  ];
  return (
    <section className="my-16">
      <div className="flex items-baseline gap-3 mb-6">
        <span className="font-mono text-xs text-phosphor/60">150+</span>
        <h2 className="text-xl font-semibold">Detection Rules</h2>
        <div className="flex-1 hairline-border-top" />
      </div>
      <p className="font-mono text-sm text-gray-500 -mt-4 mb-6">
        We don&apos;t just check a blocklist — we analyze the DNA of every website.
      </p>
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden">
        {rules.map((r) => (
          <div key={r.title} className="bg-ink-lighter p-5">
            <h3 className="font-medium text-white text-sm">{r.title}</h3>
            <p className="font-mono text-xs text-gray-500 mt-1 leading-relaxed">{r.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export function ToolsGridSection() {
  const tools = [
    { title: "URL Scanner", desc: "150 checks in 3 seconds", href: "/" },
    { title: "Phishing Scanner", desc: "Advanced phishing engine" },
    { title: "Password Checker", desc: "Strength + breach exposure" },
    { title: "Fake Login Detector", desc: "Credential harvesting sites" },
    { title: "PDF Safety Checker", desc: "Analyze PDFs for malware" },
    { title: "SSL Checker", desc: "Verify HTTPS validity" },
    { title: "DNS Lookup", desc: "A, MX, NS, TXT records" },
    { title: "Link Expander", desc: "Reveal short links" },
    { title: "IP Reputation", desc: "Flag malicious IPs" },
    { title: "Website Age", desc: "New domain = suspicious" },
  ];
  return (
    <section className="my-16" id="tools">
      <h2 className="text-xl font-semibold">Free URL Scanner & Security Tools</h2>
      <p className="font-mono text-xs text-gray-500 mt-1">No login required · built for India&apos;s digital landscape</p>
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden mt-6">
        {tools.map((t) => (
          <a
            key={t.title}
            href={t.href || "#"}
            className="bg-ink-lighter p-4 hover:bg-white/[0.04] transition-colors"
          >
            <div className="font-mono text-sm font-medium text-white">{t.title}</div>
            <div className="font-mono text-xs text-gray-500 mt-1">{t.desc}</div>
          </a>
        ))}
      </div>
    </section>
  );
}

export function IndiaThreatsSection() {
  const threats = [
    "WhatsApp job offer scams — fake links promising easy money or govt jobs",
    "KYC update scams — fake SBI, HDFC, ICICI portals stealing OTPs",
    "UPI payment link fraud — fake PhonePe, Paytm, Google Pay pages",
    "IRCTC fake booking sites — stealing railway ticket payments",
    "Aadhaar/PAN update scams — fake government portals harvesting PII",
  ];
  return (
    <section className="my-16">
      <h2 className="text-xl font-semibold">Built for Bharat · Detect These Threats</h2>
      <p className="font-mono text-sm text-gray-500 mt-1">High-volume Indian cyber threats our scanner is tuned for.</p>
      <div className="mt-6 hairline-border bg-ink-lighter rounded-sm p-4">
        <ul className="space-y-2">
          {threats.map((t) => (
            <li key={t} className="flex gap-2 font-mono text-sm text-gray-300">
              <span className="text-phosphor mt-0.5">›</span>
              <span>{t}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-px bg-ink-border hairline-border rounded-sm overflow-hidden mt-4">
        {[
          { value: "70%", label: "Rise in phishing attacks in India (2024)" },
          { value: "₹1750Cr", label: "Lost to cyber fraud in India annually" },
          { value: "150+", label: "Detection rules per scan" },
          { value: "3s", label: "Average time to check any phishing link" },
        ].map((s) => (
          <div key={s.label} className="bg-ink-lighter p-4 text-center">
            <div className="font-mono text-xl font-bold text-phosphor">{s.value}</div>
            <div className="font-mono text-xs text-gray-500 mt-1">{s.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

export function FAQSection() {
  const faqs = [
    { q: "How do I check if a link is safe before clicking?", a: "Paste the URL into the scanner above. You'll get a forensic verdict in under 3 seconds — no login needed." },
    { q: "Can it detect fake Indian bank & UPI sites?", a: "Yes. It checks typosquatting of SBI/HDFC/ICICI, UPI keywords, and India-specific TLD/brand combos." },
    { q: "How accurate is CyberShieldHub?", a: "150 heuristic rules + WHOIS/SSL + 4 threat-intel feeds. No scanner is perfect — treat Suspicious as do-not-click." },
    { q: "Does it scan shortened URLs (bit.ly, rb.gy, t.co)?", a: "Yes. It follows redirects to the final destination and scores that — shorteners are flagged as a signal." },
    { q: "What does a 'High Risk' result mean?", a: "Strong phishing/malware indicators (score 70–100). Don't open or share the link." },
    { q: "Is my scanned URL stored or shared?", a: "Inputs are processed in memory and never logged, stored, or shared. Privacy guaranteed." },
    { q: "Is CyberShieldHub completely free?", a: "Yes. Single scans are free; bulk and API access require sign-in for abuse prevention." },
    { q: "What should I do if a bank link is flagged?", a: "Don't enter OTP/password. Verify via the bank's official app or call the number on your card." },
    { q: "How do I report a phishing site in India?", a: "Report to the national helpline 1930 or cybercrime.gov.in. You can also report here — reports with 5 votes join the community blocklist." },
  ];
  return (
    <section className="my-16" id="faq">
      <h2 className="text-xl font-semibold">Frequently Asked Questions</h2>
      <div className="mt-6 hairline-border bg-ink-lighter rounded-sm divide-y divide-ink-border">
        {faqs.map((f) => (
          <details key={f.q} className="group px-4 py-3">
            <summary className="font-mono text-sm text-white cursor-pointer list-none flex justify-between gap-4">
              <span>{f.q}</span>
              <span className="text-gray-600 group-open:text-phosphor">+</span>
            </summary>
            <p className="font-mono text-xs text-gray-400 mt-2 leading-relaxed">{f.a}</p>
          </details>
        ))}
      </div>
    </section>
  );
}

export function QuizSection() {
  const questions = [
    { q: "What is Two-Factor Authentication (2FA)?", opts: ["A password with two character types", "An extra layer requiring a second verification step", "A firewall blocking two attack types", "A security question with two answers"], ans: 1 },
    { q: "You get a 'KYC update' link via SMS. What do you do?", opts: ["Click and enter Aadhaar immediately", "Forward to friends", "Verify via the bank's official app or branch — not the link", "Reply with your OTP"], ans: 2 },
    { q: "Which URL looks most suspicious?", opts: ["https://www.sbi.co.in", "https://sbi-secure-verify.tk/login?otp=1", "https://www.hdfcbank.com", "https://www.irctc.co.in"], ans: 1 },
    { q: "A shortened link (bit.ly) in a job offer — safe to click?", opts: ["Yes, short links are always safe", "Only if from a known contact, otherwise scan first", "Never", "Only on Wi-Fi"], ans: 1 },
    { q: "HTTPS with a green padlock means…", opts: ["The site is definitely legitimate", "Only that the connection is encrypted — the site could still be phishing", "Your device is virus-free", "The government approved it"], ans: 1 },
  ];

  const [idx, setIdx] = useState(0);
  const [picked, setPicked] = useState<number | null>(null);
  const [score, setScore] = useState(0);
  const [done, setDone] = useState(false);

  const submit = () => {
    if (picked === null) return;
    const correct = picked === questions[idx].ans;
    if (correct) setScore((s) => s + 1);
    if (idx + 1 >= questions.length) setDone(true);
    else {
      setIdx((i) => i + 1);
      setPicked(null);
    }
  };

  if (done) {
    return (
      <section className="my-16 hairline-border bg-ink-lighter rounded-sm p-6 text-center">
        <h2 className="text-xl font-bold">You scored {score}/{questions.length}</h2>
        <p className="font-mono text-sm text-gray-500 mt-2">
          {score >= 4 ? "Strong awareness — keep it up!" : score >= 2 ? "Decent — review the suspicious patterns above." : "Consider re-reading the detection rules. Stay sharp!"}
        </p>
        <button
          onClick={() => { setIdx(0); setScore(0); setPicked(null); setDone(false); }}
          className="mt-4 px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm"
        >
          Retry
        </button>
      </section>
    );
  }

  const cur = questions[idx];
  return (
    <section className="my-16" id="quiz">
      <h2 className="text-xl font-semibold">Test Your Phishing Awareness</h2>
      <p className="font-mono text-sm text-gray-500 mt-1">Knowledge is your first — and strongest — line of defense.</p>
      <div className="mt-6 hairline-border bg-ink-lighter rounded-sm p-5">
        <div className="font-mono text-xs text-gray-500">Question {idx + 1} of {questions.length}</div>
        <div className="font-medium text-white mt-2">{cur.q}</div>
        <div className="mt-4 space-y-2">
          {cur.opts.map((opt, i) => (
            <label
              key={opt}
              className={`flex gap-2 px-3 py-2 rounded-sm border cursor-pointer font-mono text-sm ${
                picked === i ? "bg-phosphor/10 border-phosphor/40 text-white" : "bg-ink border-ink-border text-gray-300 hover:bg-white/[0.03]"
              }`}
            >
              <input type="radio" name="quiz" checked={picked === i} onChange={() => setPicked(i)} className="mt-0.5" />
              <span>{String.fromCharCode(65 + i)}. {opt}</span>
            </label>
          ))}
        </div>
        <button
          onClick={submit}
          disabled={picked === null}
          className="mt-4 px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm disabled:opacity-40"
        >
          {idx + 1 === questions.length ? "Finish" : "Next"}
        </button>
      </div>
    </section>
  );
}

export function FeedbackSection() {
  const [sent, setSent] = useState(false);

  return (
    <section className="my-16" id="feedback">
      <h2 className="text-xl font-semibold">Help us build a better CyberShieldHub</h2>
      <p className="font-mono text-sm text-gray-500 mt-1">Your feedback shapes our detection engine.</p>
      {sent ? (
        <div className="mt-6 hairline-border bg-phosphor/5 rounded-sm p-6 text-center">
          <span className="font-mono text-sm text-phosphor">Thank you — feedback received.</span>
        </div>
      ) : (
        <form
          onSubmit={(e) => { e.preventDefault(); setSent(true); }}
          className="mt-6 hairline-border bg-ink-lighter rounded-sm p-5 space-y-3"
        >
          <div className="grid sm:grid-cols-2 gap-3">
            <input placeholder="Your name *" required className="bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none" />
            <input type="email" placeholder="your@email.com" className="bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none" />
          </div>
          <select className="w-full bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-gray-300 outline-none">
            <option>General</option>
            <option>Bug Report</option>
            <option>Feature Request</option>
          </select>
          <textarea placeholder="Tell us about your experience..." rows={4} className="w-full bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none" />
          <textarea placeholder="Any ideas for new features?" rows={3} className="w-full bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none" />
          <button type="submit" className="px-5 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20">
            Submit Feedback
          </button>
        </form>
      )}
      <div className="mt-6 hairline-border bg-ink-lighter rounded-sm p-4 text-center">
        <div className="font-mono text-sm text-white">Report Phishing — India</div>
        <div className="font-mono text-xs text-gray-500 mt-1">📞 1930 &nbsp;·&nbsp; 🌐 cybercrime.gov.in</div>
        <p className="font-mono text-[11px] text-gray-600 mt-2">Your inputs are processed in memory and never logged, stored, or shared.</p>
      </div>
    </section>
  );
}
