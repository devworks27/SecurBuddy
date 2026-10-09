import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  ShieldAlert, ShieldCheck, ShieldX, Terminal, Copy, Check,
  Send, Bot, AlertTriangle, Globe, Sparkles, Loader2,
  Database, Network, Radio, CircleDot, ChevronRight, Wifi, WifiOff,
  Search, X, Cpu, Fingerprint, Link2, Mail, Wallet, ScanLine, Info,
} from 'lucide-react';
import { analyze, getDataset, getHealth, streamChat } from './lib/api';
import CursorEffects from './components/CursorEffects';
import TiltCard from './components/TiltCard';
import MagneticButton from './components/MagneticButton';

/* ------------------------------------------------------------------ config */

const SEVERITY_STYLES = {
  critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', dot: 'bg-red-400', label: 'Critical' },
  high: { text: 'text-[#FF8A4C]', bg: 'bg-[#FF8A4C]/10', border: 'border-[#FF8A4C]/30', dot: 'bg-[#FF8A4C]', label: 'High' },
  medium: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30', dot: 'bg-amber-400', label: 'Medium' },
  low: { text: 'text-sky-400', bg: 'bg-sky-500/10', border: 'border-sky-500/30', dot: 'bg-sky-400', label: 'Low' },
  info: { text: 'text-[#7CF3C8]', bg: 'bg-[#7CF3C8]/10', border: 'border-[#7CF3C8]/30', dot: 'bg-[#7CF3C8]', label: 'Clean' },
};

const VERDICT_STYLES = {
  malicious: { ring: 'border-red-500/40', bg: 'from-red-500/10', text: 'text-red-400', icon: ShieldX },
  suspicious: { ring: 'border-[#FF8A4C]/40', bg: 'from-[#FF8A4C]/10', text: 'text-[#FF8A4C]', icon: AlertTriangle },
  clean: { ring: 'border-[#7CF3C8]/40', bg: 'from-[#7CF3C8]/10', text: 'text-[#7CF3C8]', icon: ShieldCheck },
  empty: { ring: 'border-[#B7A9DA]/20', bg: 'from-[#251A4A]/40', text: 'text-[#B7A9DA]', icon: Info },
};

const PRESET_SNIPPET = `Oct  5 12:00:23 secure-server sshd: Failed password for invalid user admin from 198.51.100.42 port 49152 ssh2
Oct  5 12:00:25 secure-server sshd: Failed password for invalid user admin from 198.51.100.42 port 49156 ssh2
Oct  5 12:00:28 secure-server sshd: Failed password for root from 198.51.100.42 port 49160 ssh2`;

const QUICK_PROMPTS = [
  '🔐 Did they break in?',
  '🛡️ Stop SSH attacks forever',
  '⚡ iptables instead of UFW',
  '🧹 Clean up ransomware',
  '🕵️ Check stolen credentials',
  '🚨 What should I do right now?',
];

const IOC_ICONS = { ips: Network, urls: Link2, emails: Mail, wallets: Wallet, domains: Globe };

/* -------------------------------------------------------------- primitives */

function Panel({ className = '', children, ...rest }) {
  return (
    <TiltCard
      className={`rounded-2xl border border-[var(--line)] bg-[var(--surface)]/70 backdrop-blur-sm shadow-xl shadow-black/20 ${className}`}
      data-hover
      {...rest}
    >
      {children}
    </TiltCard>
  );
}

function SectionTitle({ icon: Icon, children, action }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <h2 className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-widest text-slate-400">
        {Icon && <Icon className="h-3.5 w-3.5 text-emerald-400" />}
        {children}
      </h2>
      {action}
    </div>
  );
}

function CopyButton({ text, label = 'Copy', className = '' }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API needs a secure context; fall back to a temp selection.
      const area = document.createElement('textarea');
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className={`flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1.5 text-[11px] font-medium text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300 ${className}`}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : label}
    </button>
  );
}

function Spinner({ className = 'h-3.5 w-3.5' }) {
  return <Loader2 className={`${className} animate-spin`} />;
}

/* -------------------------------------------------------------- components */

function HealthPill({ health }) {
  const state = health?.status === 'ok' ? 'online' : health ? 'degraded' : 'offline';
  const map = {
    online: { cls: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10', icon: Wifi, text: 'Engine Online' },
    degraded: { cls: 'text-amber-400 border-amber-500/30 bg-amber-500/10', icon: AlertTriangle, text: 'API Unreachable' },
    offline: { cls: 'text-red-400 border-red-500/30 bg-red-500/10', icon: WifiOff, text: 'Offline' },
  };
  const { cls, icon: Icon, text } = map[state];

  return (
    <span className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${cls}`}>
      <Icon className="h-3.5 w-3.5" />
      {text}
      {health && <span className="text-slate-500">· {health.dataset_cases} cases</span>}
    </span>
  );
}

function DatasetDrawer({ cases, onPick, onClose }) {
  const [filter, setFilter] = useState('');

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return cases;
    return cases.filter(
      (c) =>
        c.description.toLowerCase().includes(q) ||
        c.type.toLowerCase().includes(q) ||
        c.id.toLowerCase().includes(q),
    );
  }, [cases, filter]);

  const TYPE_STYLES = {
    malicious_log: 'text-red-400 bg-red-500/10 border-red-500/20',
    malicious_web_log: 'text-red-400 bg-red-500/10 border-red-500/20',
    ransomware_note: 'text-red-400 bg-red-500/10 border-red-500/20',
    phishing: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    advanced_social_engineering: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    cloud_infrastructure_threat: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
    benign_log: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    edge_case_empty: 'text-slate-400 bg-slate-700/30 border-slate-600/30',
    edge_case_gibberish: 'text-slate-400 bg-slate-700/30 border-slate-600/30',
    stress_test_wall_of_text: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <button
        type="button"
        aria-label="Close dataset browser"
        className="absolute inset-0 bg-slate-950/70 backdrop-blur-sm"
        onClick={onClose}
      />
      <aside className="relative flex h-full w-full max-w-md flex-col border-l border-slate-800 bg-slate-950 shadow-2xl">
        <header className="flex items-center justify-between gap-3 border-b border-slate-800 px-5 py-4">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Golden Dataset</h3>
            <span className="rounded-md bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold text-slate-400">
              {cases.length}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="border-b border-slate-800 p-4">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Search attacks, phishings, edge cases..."
              className="w-full rounded-xl border border-slate-800 bg-slate-900 py-2 pl-9 pr-3 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
            />
          </div>
        </div>

        <div className="flex-1 space-y-2 overflow-y-auto p-4">
          {visible.length === 0 && (
            <p className="py-10 text-center text-xs text-slate-500">No cases match “{filter}”.</p>
          )}
          {visible.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => onPick(c)}
              className="group flex w-full flex-col gap-1.5 rounded-xl border border-slate-800 bg-slate-900/60 p-3 text-left transition hover:border-emerald-500/40 hover:bg-slate-900"
            >
              <div className="flex items-start justify-between gap-2">
                <span className="text-xs font-semibold text-slate-200 group-hover:text-emerald-300">
                  {c.description}
                </span>
                <ChevronRight className="h-3.5 w-3.5 shrink-0 text-slate-600 transition group-hover:translate-x-0.5 group-hover:text-emerald-400" />
              </div>
              <div className="flex items-center gap-2">
                <span className={`rounded-md border px-1.5 py-0.5 text-[10px] font-medium ${TYPE_STYLES[c.type] ?? 'text-slate-400 bg-slate-700/30 border-slate-600/30'}`}>
                  {c.type.replace(/_/g, ' ')}
                </span>
                <span className="font-mono text-[10px] text-slate-500">{c.id}</span>
              </div>
            </button>
          ))}
        </div>
      </aside>
    </div>
  );
}

function VerdictCard({ result }) {
  const style = VERDICT_STYLES[result.verdict] ?? VERDICT_STYLES.clean;
  const Icon = style.icon;
  const top = result.analysis?.matches?.[0];

  return (
    <Panel className={`relative overflow-hidden border bg-gradient-to-br ${style.ring} ${style.bg} to-transparent p-5`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className={`mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-700/50 bg-slate-950/60 ${style.text}`}>
            <Icon className="h-5 w-5" />
          </div>
          <div>
            <span className="text-[10px] font-bold uppercase tracking-widest text-slate-500">
              Verdict · {result.analysis?.match_count ?? 0} pattern{(result.analysis?.match_count ?? 0) === 1 ? '' : 's'} matched
            </span>
            <h3 className={`mt-0.5 text-lg font-bold leading-tight ${style.text}`}>
              {result.verdict_label}
            </h3>
            <p className="mt-1 text-[11px] text-slate-400">{result.message}</p>
          </div>
        </div>
        {top && (
          <span
            className={`shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide ${
              (SEVERITY_STYLES[top.severity] ?? SEVERITY_STYLES.info).text
            } ${(SEVERITY_STYLES[top.severity] ?? SEVERITY_STYLES.info).bg} ${
              (SEVERITY_STYLES[top.severity] ?? SEVERITY_STYLES.info).border
            }`}
          >
            {(SEVERITY_STYLES[top.severity] ?? SEVERITY_STYLES.info).label}
          </span>
        )}
      </div>

      {result.dataset_match && (
        <div className="mt-4 flex items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-950/60 px-3 py-2">
          <Database className="h-3.5 w-3.5 shrink-0 text-sky-400" />
          <span className="text-[11px] text-slate-400">
            Matches dataset case{' '}
            <span className="font-mono text-sky-300">{result.dataset_match.id}</span>
            <span className="text-slate-500"> · {result.dataset_match.description}</span>
          </span>
          <span className="ml-auto shrink-0 rounded-md bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-sky-400">
            {Math.round(result.dataset_match.similarity * 100)}%
          </span>
        </div>
      )}
    </Panel>
  );
}

function PlainEnglishCard({ match }) {
  if (!match) return null;
  const style = SEVERITY_STYLES[match.severity] ?? SEVERITY_STYLES.info;

  return (
    <Panel className="p-5">
      <SectionTitle icon={Sparkles}>What this actually means</SectionTitle>
      <div className="mt-3 rounded-xl border border-slate-800/80 bg-slate-950/60 p-4">
        <div className="mb-2 flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${style.dot}`} />
          <span className="text-xs font-bold text-slate-200">{match.label}</span>
          <span className="text-[10px] text-slate-500">seen {match.matches_found}×</span>
        </div>
        <p className="text-xs leading-relaxed text-slate-300">{match.explanation}</p>
      </div>
      {match.remediation && (
        <div className="mt-3 flex gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3">
          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-400" />
          <p className="text-[11px] leading-relaxed text-emerald-200/90">{match.remediation}</p>
        </div>
      )}
    </Panel>
  );
}

function DetectionsList({ matches }) {
  if (!matches?.length) return null;
  return (
    <Panel className="p-5">
      <SectionTitle icon={ScanLine}>All detections</SectionTitle>
      <ul className="mt-3 space-y-2">
        {matches.map((m) => {
          const style = SEVERITY_STYLES[m.severity] ?? SEVERITY_STYLES.info;
          return (
            <li key={m.key} className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-3">
              <div className="flex items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                <span className="text-xs font-semibold text-slate-200">{m.label}</span>
                <span className={`ml-auto rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase ${style.text} ${style.bg}`}>
                  {style.label}
                </span>
              </div>
              <p className="mt-1.5 text-[11px] leading-relaxed text-slate-400">{m.explanation}</p>
              {m.samples?.length > 0 && (
                <div className="mt-2 space-y-1">
                  {m.samples.map((s, i) => (
                    <code key={i} className="block truncate rounded-md bg-slate-900 px-2 py-1 font-mono text-[10px] text-slate-500">
                      {s}
                    </code>
                  ))}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

function IOCPanel({ iocs }) {
  const entries = Object.entries(iocs ?? {}).filter(([, v]) => v?.length);
  const total = entries.reduce((sum, [, v]) => sum + v.length, 0);

  if (total === 0) {
    return (
      <Panel className="p-5">
        <SectionTitle icon={Fingerprint}>Indicators of compromise</SectionTitle>
        <p className="mt-3 text-[11px] text-slate-500">
          No IP addresses, links, email addresses, domains, or crypto wallets were found in this content.
        </p>
      </Panel>
    );
  }

  return (
    <Panel className="p-5">
      <SectionTitle
        icon={Fingerprint}
        action={<span className="text-[10px] font-semibold text-slate-500">{total} found</span>}
      >
        Indicators of compromise
      </SectionTitle>
      <div className="mt-3 space-y-3">
        {entries.map(([kind, values]) => {
          const Icon = IOC_ICONS[kind] ?? CircleDot;
          return (
            <div key={kind}>
              <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-500">
                <Icon className="h-3 w-3" />
                {kind} <span className="text-slate-600">({values.length})</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {values.map((v) => (
                  <span
                    key={v}
                    className="max-w-full truncate rounded-md border border-slate-800 bg-slate-950 px-2 py-1 font-mono text-[11px] text-amber-300"
                  >
                    {v}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function ReputationPanel({ reputation }) {
  const ipReports = reputation?.ip_reports ?? [];
  const urlReports = reputation?.url_reports ?? [];
  const all = [...ipReports, ...urlReports];
  const skipped = [...(reputation?.skipped_ips ?? []), ...(reputation?.skipped_urls ?? [])];

  return (
    <Panel className="animate-slide-in-right p-5">
      <SectionTitle
        icon={Radio}
        action={
          <span className="flex items-center gap-1 text-[10px] text-slate-500">
            <Globe className="h-3 w-3" />
            AbuseIPDB · VirusTotal
          </span>
        }
      >
        Live threat intelligence
      </SectionTitle>

      {all.length === 0 ? (
        <p className="mt-3 text-[11px] text-slate-500">
          Nothing to look up — no public IP address or URL was extracted from this content.
        </p>
      ) : (
        <div className="stagger-children mt-4 space-y-3">
          {all.map((r, idx) => {
            const value = r.ip ?? r.url;
            const score = r.abuse_confidence_score;
            const malicious = r.verdict === 'malicious';
            const reserved = r.status === 'reserved_range';
            const isDangerous = malicious || (score !== null && score >= 80);
            const isWarning = score !== null && score >= 30 && score < 80;

            return (
              <div
                key={`${value}-${idx}`}
                className={`animate-slide-in-right overflow-hidden rounded-2xl border p-4 transition-all duration-300 ${
                  isDangerous
                    ? 'border-red-500/40 bg-gradient-to-r from-red-500/10 to-red-500/5 hover:border-red-500/60'
                    : reserved
                      ? 'border-slate-700/60 bg-slate-900/40'
                      : isWarning
                        ? 'border-amber-500/30 bg-gradient-to-r from-amber-500/10 to-amber-500/5 hover:border-amber-500/50'
                        : 'border-emerald-500/20 bg-gradient-to-r from-emerald-500/10 to-emerald-500/5 hover:border-emerald-500/40'
                }`}
              >
                {/* IP Address - Prominent */}
                <div className="mb-3 flex items-start gap-3">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-950/80 border border-slate-700/50">
                    {r.ip ? <Network className="h-4 w-4 text-cyan-400" /> : <Link2 className="h-4 w-4 text-purple-400" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-sm font-semibold text-white">{value}</div>
                    {r.verdict && (
                      <span className="mt-1 inline-block rounded-md bg-slate-800 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-slate-300">
                        {r.verdict}
                      </span>
                    )}
                    {r.is_tor && (
                      <span className="ml-1 mt-1 inline-block rounded-md bg-purple-500/20 px-2 py-0.5 text-[10px] font-bold text-purple-300">
                        TOR EXIT
                      </span>
                    )}
                  </div>
                </div>

                {/* Abuse Confidence Score - Large & Visible */}
                {score !== null && score !== undefined && (
                  <div className="mb-3 rounded-xl border border-slate-800 bg-slate-950/80 p-3">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-bold uppercase tracking-widest text-slate-400">
                        Abuse Confidence Score
                      </span>
                      <span
                        className={`text-2xl font-black leading-none ${
                          score >= 80 ? 'text-red-400' : score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}
                      >
                        {score}%
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          score >= 80
                            ? 'bg-gradient-to-r from-red-500 to-red-400'
                            : score >= 30
                              ? 'bg-gradient-to-r from-amber-500 to-amber-400'
                              : 'bg-gradient-to-r from-emerald-500 to-emerald-400'
                        }`}
                        style={{ width: `${score}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Threat Metadata Grid */}
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {r.total_reports > 0 && (
                    <div className="rounded-lg bg-slate-950/60 px-2.5 py-2">
                      <div className="text-[9px] font-bold uppercase tracking-wide text-slate-500">Reports</div>
                      <div className="text-sm font-bold text-red-400">{r.total_reports}</div>
                    </div>
                  )}
                  {r.isp && (
                    <div className="rounded-lg bg-slate-950/60 px-2.5 py-2">
                      <div className="text-[9px] font-bold uppercase tracking-wide text-slate-500">ISP</div>
                      <div className="truncate text-xs font-semibold text-slate-300">{r.isp}</div>
                    </div>
                  )}
                  {r.country_code && (
                    <div className="rounded-lg bg-slate-950/60 px-2.5 py-2">
                      <div className="text-[9px] font-bold uppercase tracking-wide text-slate-500">Country</div>
                      <div className="text-xs font-semibold text-slate-300">{r.country_code}</div>
                    </div>
                  )}
                  {r.usage_type && (
                    <div className="rounded-lg bg-slate-950/60 px-2.5 py-2">
                      <div className="text-[9px] font-bold uppercase tracking-wide text-slate-500">Type</div>
                      <div className="truncate text-xs font-semibold text-slate-300">{r.usage_type}</div>
                    </div>
                  )}
                </div>

                {/* Summary */}
                <p className="mt-3 text-xs leading-relaxed text-slate-300">{r.summary}</p>

                {r.permalink && (
                  <a
                    href={r.permalink}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-sky-400 underline underline-offset-2 hover:text-sky-300"
                  >
                    View on VirusTotal →
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}

      {skipped.length > 0 && (
        <p className="mt-4 flex items-start gap-1.5 text-[10px] leading-relaxed text-slate-600 animate-fade-in">
          <Info className="mt-0.5 h-3 w-3 shrink-0" />
          {skipped.length} further indicator(s) skipped to stay inside free-tier API limits:{' '}
          <span className="font-mono">{skipped.join(', ')}</span>
        </p>
      )}
    </Panel>
  );
}

function RemediationPanel({ remediation }) {
  const [active, setActive] = useState(0);
  const variants = remediation?.variants ?? [];

  if (!variants.length || !remediation?.primary) {
    return (
      <Panel className="p-5">
        <SectionTitle icon={Terminal}>Remediation commands</SectionTitle>
        <p className="mt-3 text-[11px] leading-relaxed text-slate-500">{remediation?.note}</p>
      </Panel>
    );
  }

  const current = variants[Math.min(active, variants.length - 1)];

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-xl shadow-black/20">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-slate-950/70 px-4 py-3">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-emerald-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">Block it now</span>
        </div>
        <CopyButton text={current.command} />
      </div>

      <div className="flex gap-1 overflow-x-auto border-b border-slate-800 bg-slate-950/40 px-3 pt-3">
        {variants.map((v, i) => (
          <button
            key={i}
            type="button"
            onClick={() => setActive(i)}
            className={`shrink-0 rounded-t-lg border border-b-0 px-3 py-1.5 text-[11px] font-medium transition ${
              i === active
                ? 'border-slate-700 bg-slate-900 text-emerald-300'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            }`}
          >
            {v.tool}
            <span className="ml-1.5 text-[9px] text-slate-600">{v.os}</span>
          </button>
        ))}
      </div>

      <pre className="overflow-x-auto bg-slate-950/80 p-4">
        <code className="font-mono text-[11px] leading-relaxed text-emerald-400">{current.command}</code>
      </pre>

      {remediation.note && (
        <div className="flex gap-2 border-t border-slate-800 bg-slate-950/60 px-4 py-3">
          <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-400" />
          <p className="text-[11px] leading-relaxed text-slate-400">{remediation.note}</p>
        </div>
      )}
    </div>
  );
}

/* --------------------------------------------------------------- main app */

export default function App() {
  const [logInput, setLogInput] = useState('');
  const [result, setResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);

  const [cases, setCases] = useState([]);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [health, setHealth] = useState(null);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content:
        "👋 Hey there! I'm **SecurBuddy**, your AI security companion.\n\n🎯 **What I do:** Paste any suspicious log, email, or weird message on the left. I'll instantly analyze it, extract the bad stuff, check live threat feeds, and give you the **exact command** to block the attacker.\n\n💬 **Ask me anything:** How to harden your system, clean up infections, or understand what just happened. I'm here to help! ⚡",
    },
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatBusy, setChatBusy] = useState(false);

  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    let cancelled = false;
    getHealth()
      .then((h) => !cancelled && setHealth(h))
      .catch(() => !cancelled && setHealth(null));
    getDataset()
      .then((d) => !cancelled && setCases(d.cases ?? []))
      .catch(() => !cancelled && setCases([]));
    return () => {
      cancelled = true;
    };
  }, []);

  const runAnalysis = useCallback(async ({ rawContent = '', datasetId = null }) => {
    setAnalyzing(true);
    setError(null);
    try {
      const data = await analyze({ rawContent, datasetId });
      setResult(data);
      if (rawContent) setLogInput(rawContent);
    } catch (err) {
      setError(err.message ?? 'Analysis failed.');
      setResult(null);
    } finally {
      setAnalyzing(false);
    }
  }, []);

  const handleSend = useCallback(
    (override) => {
      const text = (override ?? chatInput).trim();
      if (!text || chatBusy) return;

      const history = messages.map(({ role, content }) => ({ role, content }));
      const context = result
        ? JSON.stringify({
            detections: (result.analysis?.matches ?? []).map((m) => ({
              threat: m.label,
              severity: m.severity,
              occurrences: m.matches_found,
            })),
            indicators_of_compromise: result.iocs,
            live_reputation: {
              ip_reports: result.reputation?.ip_reports ?? [],
              url_reports: result.reputation?.url_reports ?? [],
            },
            recommended_block: result.remediation?.primary ?? null,
          })
        : null;

      setMessages((prev) => [...prev, { role: 'user', content: text }, { role: 'assistant', content: '' }]);
      setChatInput('');
      setChatBusy(true);

      let acc = '';
      streamChat(
        { history, userMessage: text, analysisContext: context },
        {
          onToken: (token) => {
            acc += token;
            setMessages((prev) => {
              const next = [...prev];
              next[next.length - 1] = { role: 'assistant', content: acc };
              return next;
            });
          },
          onError: (msg) => {
            setMessages((prev) => {
              const next = [...prev];
              next[next.length - 1] = {
                role: 'assistant',
                content: acc || `⚠️ ${msg}`,
              };
              return next;
            });
          },
          onDone: () => setChatBusy(false),
        },
      );
    },
    [chatInput, chatBusy, messages, result],
  );

  const topMatch = result?.analysis?.matches?.[0];

  return (
    <div className="min-h-screen bg-[var(--ink)] text-[var(--text)]">
      <CursorEffects />
      {/* ambient background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-40 -top-40 h-96 w-96 rounded-full bg-[#FF8A4C]/5 blur-3xl" />
        <div className="absolute -bottom-40 -right-40 h-96 w-96 rounded-full bg-[#7CF3C8]/5 blur-3xl" />
      </div>

      <header className="sticky top-0 z-40 border-b border-[var(--line)] bg-[var(--ink)]/80 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4 px-5 py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[var(--tangerine)]/30 bg-[var(--tangerine)]/10 text-[var(--tangerine)]">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h1 className="font-[family-name:var(--display)] text-base font-bold tracking-wide text-white">SecurBuddy</h1>
              <p className="text-[11px] text-[var(--muted)]">Autonomous incident triage &amp; AI copilot</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <HealthPill health={health} />
            <button
              type="button"
              onClick={() => setDrawerOpen(true)}
              className="flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-[11px] font-semibold text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300"
            >
              <Database className="h-3.5 w-3.5" />
              Dataset
              <span className="rounded bg-slate-800 px-1 text-[10px] text-slate-400">{cases.length}</span>
            </button>
          </div>
        </div>
      </header>

      <main className="relative mx-auto grid max-w-[1600px] grid-cols-1 gap-5 p-5 xl:grid-cols-12">
        {/* ------------------------------------------------ analysis column */}
        <section className="flex flex-col gap-5 xl:col-span-7 2xl:col-span-8">
          <Panel className="p-5">
            <SectionTitle
              icon={ScanLine}
              action={
                <button
                  type="button"
                  onClick={() => setLogInput(PRESET_SNIPPET)}
                  className="text-[11px] text-emerald-400 underline underline-offset-2 transition hover:text-emerald-300"
                >
                  Load sample log
                </button>
              }
            >
              Ingest suspicious content
            </SectionTitle>

            <textarea
              value={logInput}
              onChange={(e) => setLogInput(e.target.value)}
              placeholder="Paste server logs (auth.log, syslog, nginx, CloudTrail), an email, or any suspicious message..."
              rows={5}
              spellCheck={false}
              className="mt-3 w-full resize-y rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-[11px] leading-relaxed text-slate-300 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
            />

            <div className="mt-3 flex items-center justify-between gap-3">
              <span className="text-[10px] text-slate-600">
                {logInput.length.toLocaleString()} characters
                {result?.stats?.truncated && ' · truncated at 20,000'}
              </span>
              <button
                type="button"
                onClick={() => runAnalysis({ rawContent: logInput })}
                disabled={analyzing || !logInput.trim()}
                className="flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-emerald-500/10 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {analyzing ? <Spinner /> : <ShieldCheck className="h-4 w-4" />}
                {analyzing ? 'Scanning…' : 'Analyze incident'}
              </button>
            </div>
          </Panel>

          {error && (
            <Panel className="border-red-500/40 bg-red-500/5 p-4">
              <div className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
                <div>
                  <p className="text-xs font-bold text-red-300">{error}</p>
                  <p className="mt-1 text-[11px] text-red-200/70">
                    Make sure the backend is running:{' '}
                    <code className="font-mono">uvicorn main:app --reload</code> inside{' '}
                    <code className="font-mono">Backend/</code>.
                  </p>
                </div>
              </div>
            </Panel>
          )}

          {analyzing && (
            <Panel className="space-y-3 p-5">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="animate-pulse space-y-2">
                  <div className="h-3 w-1/3 rounded bg-slate-800" />
                  <div className="h-2.5 w-full rounded bg-slate-800/60" />
                  <div className="h-2.5 w-4/5 rounded bg-slate-800/40" />
                </div>
              ))}
            </Panel>
          )}

          {!analyzing && result && result.status !== 'empty' && (
            <>
              <VerdictCard result={result} />
              <PlainEnglishCard match={topMatch} />
              <DetectionsList matches={result.analysis?.matches} />
              <IOCPanel iocs={result.iocs} />
              <ReputationPanel reputation={result.reputation} />
              <RemediationPanel
                key={result.remediation?.primary?.command ?? 'none'}
                remediation={result.remediation}
              />
            </>
          )}

          {!analyzing && !result && !error && (
            <Panel className="flex flex-col items-center justify-center gap-3 p-12 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900">
                <Cpu className="h-6 w-6 text-slate-600" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-300">No analysis yet</p>
                <p className="mt-1 max-w-sm text-[11px] leading-relaxed text-slate-500">
                  Paste a log, an email, or a suspicious message — or pick a case from the golden dataset
                  to see how the engine classifies real attack patterns.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setDrawerOpen(true)}
                className="mt-1 flex items-center gap-1.5 rounded-xl border border-slate-700 bg-slate-900 px-3 py-1.5 text-[11px] font-semibold text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300"
              >
                <Database className="h-3.5 w-3.5" />
                Browse dataset
              </button>
            </Panel>
          )}
        </section>

        {/* ---------------------------------------------------- chat column */}
        <section className="xl:col-span-5 2xl:col-span-4">
          <Panel className="flex h-[calc(100vh-6.5rem)] min-h-[560px] flex-col overflow-hidden xl:sticky xl:top-20">
            <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-950/50 px-4 py-3">
              <Bot className="h-5 w-5 text-emerald-400" />
              <div className="min-w-0 flex-1">
                <h2 className="text-xs font-bold uppercase tracking-wide text-slate-100">Incident Copilot</h2>
                <p className="truncate text-[10px] text-slate-500">
                  {result ? 'Grounded in your latest analysis' : 'Ask anything about threats & cleanup'}
                </p>
              </div>
              {result && (
                <span className="shrink-0 rounded-md bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-400">
                  context on
                </span>
              )}
            </div>

            <div className="flex-1 space-y-3 overflow-y-auto p-4">
              {messages.map((m, i) => (
                <div key={i} className={`flex gap-2.5 ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  {m.role === 'assistant' && (
                    <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
                      <Bot className="h-3.5 w-3.5" />
                    </div>
                  )}
                  <div
                    className={`max-w-[88%] rounded-2xl px-3.5 py-2.5 text-xs leading-relaxed ${
                      m.role === 'user'
                        ? 'rounded-br-md bg-emerald-500 font-medium text-slate-950'
                        : 'rounded-bl-md border border-slate-800 bg-slate-950 text-slate-200'
                    }`}
                  >
                    {m.role === 'user' ? (
                      <span className="whitespace-pre-wrap break-words">{m.content}</span>
                    ) : (
                      <div className="prose-chat">
                        <ReactMarkdown
                          components={{
                            p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                            ul: ({ children }) => <ul className="mb-2 list-disc space-y-1 pl-4 last:mb-0">{children}</ul>,
                            ol: ({ children }) => <ol className="mb-2 list-decimal space-y-1 pl-4 last:mb-0">{children}</ol>,
                            li: ({ children }) => <li>{children}</li>,
                            strong: ({ children }) => <strong className="font-semibold text-emerald-300">{children}</strong>,
                            code: ({ children }) => (
                              <code className="rounded bg-slate-900 px-1 py-0.5 font-mono text-[11px] text-amber-300">
                                {children}
                              </code>
                            ),
                            pre: ({ children }) => (
                              <pre className="my-2 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                                {children}
                              </pre>
                            ),
                            a: ({ children, href }) => (
                              <a href={href} target="_blank" rel="noreferrer noopener" className="text-sky-400 underline underline-offset-2">
                                {children}
                              </a>
                            ),
                          }}
                        >
                          {m.content}
                        </ReactMarkdown>
                        {chatBusy && i === messages.length - 1 && m.content === '' && (
                          <span className="inline-block h-3 w-1.5 animate-pulse bg-emerald-400 align-middle" />
                        )}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>

            <div className="flex flex-wrap gap-1.5 border-t border-slate-800/80 bg-slate-950/40 p-2.5">
              {QUICK_PROMPTS.map((p) => (
                <button
                  key={p}
                  type="button"
                  onClick={() => handleSend(p)}
                  disabled={chatBusy}
                  className="rounded-lg border border-slate-700/50 bg-slate-800/90 px-2.5 py-1 text-left text-[11px] text-slate-300 transition hover:border-emerald-500/40 hover:text-emerald-300 disabled:opacity-40"
                >
                  {p}
                </button>
              ))}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="flex gap-2 border-t border-slate-800 bg-slate-950 p-3"
            >
              <input
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask how to block this or clean up..."
                className="flex-1 rounded-xl border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
              />
              <button
                type="submit"
                disabled={!chatInput.trim() || chatBusy}
                className="flex items-center justify-center rounded-xl bg-emerald-500 px-3 py-2 text-slate-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {chatBusy ? <Spinner /> : <Send className="h-4 w-4" />}
              </button>
            </form>
          </Panel>
        </section>
      </main>

      {drawerOpen && (
        <DatasetDrawer
          cases={cases}
          onClose={() => setDrawerOpen(false)}
          onPick={(c) => {
            setDrawerOpen(false);
            setLogInput(c.raw_input ?? '');
            runAnalysis({ datasetId: c.id });
          }}
        />
      )}
    </div>
  );
}