import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

// Final pass III.0 item 7: the Reports section is gone (nothing may imply
// a report workflow exists).
const SECTIONS = [
  { id: 'queue', label: 'Queue' },
  { id: 'game-modes', label: 'Game Modes' },
  { id: 'siem', label: 'SIEM Workbench' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'analytics', label: 'Analytics' },
];

const Section = ({ id, title, children }) => (
  <section id={id} className="scroll-mt-24 mt-16">
    <h2 className="text-2xl font-medium text-[#1a2332] mb-5">{title}</h2>
    <div className="space-y-4 text-[#57606a] text-base leading-relaxed">{children}</div>
  </section>
);

const Docs = () => {
  const [active, setActive] = useState('queue');

  // Scroll-spy: highlight the section currently in view.
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) setActive(e.target.id);
        });
      },
      { rootMargin: '-15% 0px -75% 0px', threshold: 0 }
    );
    SECTIONS.forEach((s) => {
      const el = document.getElementById(s.id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);

  // Honor a hash arriving from the landing (/docs#queue etc.)
  useEffect(() => {
    const { hash } = window.location;
    if (hash) {
      const el = document.getElementById(hash.slice(1));
      if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth' }), 0);
    }
  }, []);

  const goTo = (e, id) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
      window.history.replaceState(null, '', `#${id}`);
    }
  };

  return (
    <div className="min-h-screen bg-white text-[#1a2332]" style={{ fontFamily: "'Inter', sans-serif" }}>
      {/* Mobile top bar */}
      <div className="lg:hidden sticky top-0 z-20 flex items-center justify-between px-5 py-3.5 bg-[#101218] border-b border-white/10 text-white">
        <Link to="/" className="flex items-center gap-2.5">
          <img src="/spectyr_logo.png" alt="" className="h-9 w-9 object-contain" />
          <span className="text-lg font-semibold" style={{ fontFamily: "'Space Grotesk', 'Inter', sans-serif", letterSpacing: '0.06em' }}>SPECTR</span>
        </Link>
        <Link
          to="/sim"
          className="liquid-btn inline-flex items-center gap-2 rounded-full px-4 py-1.5 text-sm font-medium text-white"
        >
          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z" /></svg>
          Start Sim
        </Link>
      </div>

      <div className="flex">
        {/* Sidebar */}
        <aside className="hidden lg:flex flex-col shrink-0 w-64 sticky top-0 h-screen bg-[#101218] text-white px-8 py-12">
          <Link to="/" className="flex items-center gap-3 mb-12">
            <img src="/spectyr_logo.png" alt="" className="h-14 w-14 object-contain" />
            <span className="text-xl font-semibold" style={{ fontFamily: "'Space Grotesk', 'Inter', sans-serif", letterSpacing: '0.06em' }}>SPECTR</span>
          </Link>

          <nav className="flex flex-col gap-2">
            {SECTIONS.map((s) => (
              <a
                key={s.id}
                href={`#${s.id}`}
                onClick={(e) => goTo(e, s.id)}
                className={`text-sm transition-colors ${
                  active === s.id ? 'text-white font-medium' : 'text-gray-400 hover:text-white'
                }`}
              >
                {s.label}
              </a>
            ))}
          </nav>

          <Link
            to="/sim"
            className="liquid-btn mt-auto inline-flex items-center justify-center gap-2 rounded-full px-5 py-2 text-sm font-medium text-white"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z" /></svg>
            Start Sim
          </Link>
        </aside>

        {/* Content */}
        <main className="flex-1 min-w-0 px-6 sm:px-10 lg:px-20 py-14 lg:py-24">
          <div className="max-w-2xl">
            <h1 className="text-5xl sm:text-6xl font-light tracking-tight text-[#1a2332] mb-8">
              How Spectyr Works
            </h1>
            <div className="space-y-4 text-[#57606a] text-lg leading-relaxed">
              <p>
                Spectyr puts you in the role of a Tier 1 SOC analyst. Events stream into a simulated
                SIEM, mixing routine network activity with active threats.
              </p>
              <p>
                Investigate incidents, follow related users, hosts, and IPs, classify each one,
                and submit your verdict.
              </p>
            </div>

            <Section id="queue" title="Queue">
              <p>
                A Hardcore run contains 10 scenarios selected from a catalog of 20,
                including one or two false positives. Guided mode runs a single scenario you choose.
              </p>
              <p>
                Scenarios arrive every 20 to 40 seconds, with up to three open at once. Complete all
                10 to finish the run.
              </p>
              <p>
                Attack events are mixed into normal traffic. Use shared entities such as users,
                hosts, and IP addresses to uncover the full chain.
              </p>
            </Section>

            <Section id="game-modes" title="Game Modes">
              <div>
                <p className="text-[#1a2332] font-medium mb-1">Guided</p>
                <p>Pick one scenario from the catalog and work it with unlimited time. Hints are available while you investigate; your classification is graded when you submit the incident.</p>
              </div>
              <div>
                <p className="text-[#1a2332] font-medium mb-1">Hardcore</p>
                <p>A queue of alerts is pushed to you under a single 15-minute timer; only the trigger evidence arrives first. Pivot through the event stream to reconstruct each chain. One wrong classification or an expired timer ends the run.</p>
              </div>
            </Section>

            <Section id="siem" title="SIEM Workbench">
              <p>
                The SIEM tab is an investigation workbench over the session event pool. Queries are
                written in LCQL, four segments joined by pipes:
              </p>
              <p className="log-mono text-[#1a2332]">TIMEFRAME | SENSOR | EVENT TYPE | FILTERS</p>
              <p>
                Run Query executes the bar as a frozen snapshot: results never move until you run
                again, and when new matching telemetry arrives a count appears with a Load new
                events action that brings the snapshot up to date. Sidebar values and per-field
                inspector actions refine the executed
                query; entity pivots (host, account, IP, domain, process, file, event type, sensor)
                follow the clue across the evidence you are searching. With an incident selected
                the SIEM searches that incident&apos;s evidence; with none it searches all activity.
                Investigate in SIEM on an incident or detection opens the SIEM with that
                evidence already searched.
              </p>
              <p>
                Simple search accepts a filter expression. Advanced LCQL accepts the complete
                four-part query.
              </p>
              <p>
                Quoting rules for filter values: values containing spaces or any of{' '}
                <span className="log-mono">&quot; &#39; = ! | *</span> must be quoted, and the bare
                words and, or, not, contains must be quoted to match literally. Double-quoted and
                unquoted values match case-insensitively; single quotes match exactly.
              </p>
            </Section>

            <Section id="scenarios" title="Scenarios">
              <p>Spectyr includes 15 attack scenarios across eight categories:</p>
              <p className="text-[#1a2332]">
                Malware, Phishing, Defense Evasion, Lateral Movement, Command and Control, Brute
                Force, Data Exfiltration, and Insider Threat.
              </p>
              <p>
                The scenarios use simulated telemetry from Sysmon, Windows Security, Proxy, DNS,
                Firewall, and Azure AD.
              </p>
              <p>
                Each run also includes benign activity that triggered a real detection rule.
                Correctly dismissing a false positive improves your score. Escalating one counts as
                an incorrect decision.
              </p>
              <p>
                After each scenario, you receive a triage review with the related MITRE ATT&amp;CK
                technique, a short explanation, and recommended response steps.
              </p>
            </Section>

            <Section id="analytics" title="Analytics">
              <p>Every decision is recorded as:</p>
              <div className="space-y-1 text-[#1a2332]">
                <p>Correct</p>
                <p>Missed threat</p>
                <p>False positive caught</p>
                <p>False positive escalated</p>
              </div>
              <p>Your analytics show accuracy, queue progress, recent decisions, and final grade.</p>
            </Section>

          </div>
        </main>
      </div>
    </div>
  );
};

export default Docs;
