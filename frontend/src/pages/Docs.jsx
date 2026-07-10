import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const SECTIONS = [
  { id: 'queue', label: 'Queue' },
  { id: 'game-modes', label: 'Game Modes' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'reports', label: 'Reports' },
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
          <span className="text-lg font-medium">Spectyr</span>
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
            <span className="text-xl font-medium tracking-tight">Spectyr</span>
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
              How Spectyr works
            </h1>
            <p className="text-[#57606a] text-lg leading-relaxed">
              Spectyr puts you in a Tier-1 SOC analyst's seat. Events stream into your queue the
              way they do on a real SIEM, mostly routine noise from a simulated network. Somewhere
              in it, an attack is unfolding on one machine. Investigate the alerts, classify the
              threat or flag a false positive, then file a short report and move on.
            </p>

            <Section id="queue" title="Queue">
              <p>
                Each run is a queue of ten scenarios, pulled from a catalog of twenty and shuffled,
                with one or two false positives in the mix. No two runs are alike.
              </p>
              <p>
                Scenarios arrive twenty to forty seconds apart, up to three open at once. Clear all
                ten to finish.
              </p>
              <p>
                An attack's events scatter through normal traffic, tied together by a shared user,
                host, and IP. Pivot on those to pull the chain out of the noise.
              </p>
            </Section>

            <Section id="game-modes" title="Game Modes">
              <p>
                <span className="text-[#1a2332] font-medium">Training.</span> Unlimited time and
                feedback after every call. The attack chain is grouped for you.
              </p>
              <p>
                <span className="text-[#1a2332] font-medium">Hardcore.</span> One 15:00 timer for
                the whole queue. A single wrong call, or time running out, ends the run.
              </p>
              <p>
                <span className="text-[#1a2332] font-medium">Analyst.</span> Only the trigger alert
                shows. Pivot through the events to rebuild the chain yourself.
              </p>
            </Section>

            <Section id="scenarios" title="Scenarios">
              <p>
                Fifteen attack scenarios span eight categories, built from real telemetry across
                Sysmon, Windows Security, Proxy, DNS, Firewall, and Azure AD.
              </p>
              <p className="text-[#1a2332]">
                Malware, Phishing, Defense Evasion, Lateral Movement, Command and Control, Brute
                Force, Data Exfiltration, and Insider Threat.
              </p>
              <p>
                Every run also mixes in a false positive or two: benign activity that trips a real
                rule. Dismiss one and it scores like catching an attack. Escalate it and it counts
                against you.
              </p>
              <p>
                After each scenario you get a triage review: the MITRE ATT&amp;CK technique, a short
                read on the attack, and the response a real team would run.
              </p>
            </Section>

            <Section id="analytics" title="Analytics">
              <p>
                Every call lands in one of four buckets: correct, missed, false positive caught, or
                false positive escalated. Accuracy is correct plus false positives caught, over
                total calls.
              </p>
              <p>
                The tab tracks your report card, results, queue progress, and recent decisions.
                Finish a run for a final grade.
              </p>
            </Section>

            <Section id="reports" title="Reports">
              <p>
                Triage is half the job. The other half is writing it up. File a report for each
                scenario covering what happened, who it hit, and how you handled it. Edit, track
                status, and export to PDF.
              </p>
            </Section>
          </div>
        </main>
      </div>
    </div>
  );
};

export default Docs;
