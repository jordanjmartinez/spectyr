import React, { useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';

const NAV = [
  { id: 'queue', label: 'Queue' },
  { id: 'game-modes', label: 'Game Modes' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'analytics', label: 'Analytics' },
  { id: 'reports', label: 'Reports' },
];

const QUEUE_FACTS = [
  ['Queue length', '10 scenarios per run'],
  ['Catalog', '20 scenarios — 15 attack chains + 5 false positives'],
  ['False positives', '1–2 mixed into every run'],
  ['In flight at once', 'Up to 3 unresolved scenarios'],
];

const CATEGORIES = [
  ['Malware', 'Malicious code on an endpoint — from USB-delivered payloads to ransomware staging.'],
  ['Phishing', 'Credential lures and malicious attachments arriving by mail or link.'],
  ['Defense Evasion', 'Attackers switching off protections or clearing logs to cover their tracks.'],
  ['Lateral Movement', 'Compromised accounts hopping between workstations and servers.'],
  ['Command & Control', 'Implants phoning home over HTTP beacons or DNS tunnels.'],
  ['Brute Force', 'Password guessing and spraying against exposed accounts.'],
  ['Data Exfiltration', 'Sensitive files archived and pushed out of the network.'],
  ['Insider Threat', 'Legitimate users staging data or standing up shadow IT.'],
];

const FALSE_POSITIVES = [
  'An authorized security exercise generating test detections',
  'A legitimate bulk file migration that looks like mass data movement',
  'Backup software whose scheduled check-ins look like C2 beaconing',
  'Modern OAuth sign-in flows tripping identity anomaly rules',
  'A proxy SSL-inspection change that floods certificate alerts',
];

const Section = ({ id, title, children }) => (
  <section id={id} className="scroll-mt-28 mt-12 pt-12 border-t border-[#e2e6ea]">
    <h2 className="text-2xl font-semibold text-[#1a2332] mb-4">{title}</h2>
    <div className="space-y-4 text-[#57606a] leading-relaxed">{children}</div>
  </section>
);

const Docs = () => {
  const { hash } = useLocation();

  // Scroll to the section named in the URL hash (router navigation doesn't do this itself)
  useEffect(() => {
    if (!hash) {
      window.scrollTo(0, 0);
      return;
    }
    const el = document.getElementById(hash.slice(1));
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [hash]);

  return (
    <div className="min-h-screen bg-[#f6f8fa] text-[#1a2332]">
      {/* Sticky navy chrome header, echoing the sim's nav rail */}
      <header className="sticky top-0 z-50 bg-[#101218]/95 backdrop-blur-md border-b border-white/10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center justify-between gap-4">
          <Link to="/" className="flex items-center gap-2 shrink-0">
            <img src="/spectyr_logo.png" alt="" className="h-8 w-8 object-contain" />
            <span className="text-xl font-semibold tracking-tight text-white" style={{ fontFamily: "'IBM Plex Sans', sans-serif" }}>
              Spectyr
            </span>
          </Link>
          <nav className="hidden md:flex items-center gap-6">
            {NAV.map(({ id, label }) => (
              <Link
                key={id}
                to={`/docs#${id}`}
                className="text-sm text-gray-300 hover:text-white transition-colors"
              >
                {label}
              </Link>
            ))}
          </nav>
          <Link
            to="/sim"
            className="bg-white hover:bg-gray-100 text-[#101218] text-sm font-medium rounded-full px-5 py-2 transition-colors whitespace-nowrap"
          >
            Launch Sim
          </Link>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-6 py-12">
        <h1 className="text-3xl md:text-4xl font-semibold text-[#1a2332] mb-4">
          How Spectyr works
        </h1>
        <p className="text-[#57606a] leading-relaxed">
          Spectyr puts you in the seat of a Tier-1 SOC analyst. Security events stream into your
          queue the way they do on a production SIEM — most of it routine noise from a simulated
          corporate network. Buried in that noise, an attack chain unfolds on one employee's
          machine. Your job: spot it, investigate it, and make the right call.
        </p>
        <div className="mt-6 rounded-xl bg-white border border-[#e2e6ea] p-6" style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
          <p className="text-sm font-medium text-[#1a2332] mb-3">The loop</p>
          <ol className="list-decimal list-inside space-y-2 text-sm text-[#57606a]">
            <li>Start the sim, pick a game mode, and sign in with your analyst name.</li>
            <li>Watch the Alert Queue as events stream in from across the network.</li>
            <li>A scenario begins — an attack chain (or a false alarm) hidden in the noise.</li>
            <li>Investigate the related alerts, then classify the threat category — or flag the whole thing as a false positive.</li>
            <li>Read the triage review, file your incident report, and keep working as the next alerts drip in.</li>
          </ol>
        </div>

        <Section id="queue" title="The Alert Queue">
          <p>
            Each run builds a queue of ten scenarios, drawn at random from a catalog of twenty —
            fifteen attack chains and five false positives — then shuffled, with one or two false
            positives guaranteed in the mix. No two runs play the same, and you can never assume an
            alert storm is real.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm border border-[#e2e6ea] rounded-lg overflow-hidden">
              <tbody>
                {QUEUE_FACTS.map(([fact, value]) => (
                  <tr key={fact} className="border-t border-[#e2e6ea] first:border-t-0">
                    <td className="px-4 py-2 font-medium text-[#1a2332] bg-[#f0f2f5] w-40 sm:w-56 align-top">{fact}</td>
                    <td className="px-4 py-2 text-[#57606a]">{value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p>
            Scenarios don't all land at once. They drip into your queue twenty to forty seconds
            apart, with at most three unresolved at any time, so the pressure builds as you work.
            Classify or dismiss a scenario and it clears; resolve all ten and the run is complete.
          </p>
          <p>
            Attack events don't arrive in a tidy batch either. They're scattered through normal
            traffic a few events apart, with progressing timestamps — and the whole chain stays
            tied to the same employee, workstation, and source IP. Pivoting on those shared
            indicators is how you separate the chain from the noise.
          </p>
          <p>
            When a category comes up more than once, the scenario doesn't: one malware run might be
            a USB-delivered payload while another is ransomware staging. Every scenario in the
            catalog is unique.
          </p>
        </Section>

        <Section id="game-modes" title="Game Modes">
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="rounded-xl bg-white border border-[#e2e6ea] p-5" style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
              <p className="font-medium text-[#1a2332] mb-2">Training Mode</p>
              <p className="text-sm">
                Unlimited time and continuous feedback on every decision, with no penalties. Learn
                the log sources, practice pivoting on indicators, and get comfortable with the
                triage flow.
              </p>
            </div>
            <div className="rounded-xl bg-white border border-[#e2e6ea] p-5" style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
              <p className="font-medium text-[#1a2332] mb-2">Hardcore Mode</p>
              <p className="text-sm">
                A single 15:00 timer covers the whole queue, and it's one-strike: one wrong
                classification — or the clock reaching zero — ends the run. Retrying starts a fresh
                queue from scratch. The countdown shifts color as time runs low.
              </p>
            </div>
          </div>
          <p>
            Start in Training to learn the patterns; move to Hardcore when you want the pressure of
            a real queue.
          </p>
        </Section>

        <Section id="scenarios" title="Scenarios">
          <p>
            Fifteen unique attack scenarios span eight categories, built from realistic telemetry:
            Sysmon, Windows Security, Proxy, DNS, Firewall, and Azure AD events.
          </p>
          <dl className="grid sm:grid-cols-2 gap-3">
            {CATEGORIES.map(([name, desc]) => (
              <div key={name} className="rounded-lg bg-white border border-[#e2e6ea] px-4 py-3">
                <dt className="text-sm font-medium text-[#1a2332]">{name}</dt>
                <dd className="text-sm mt-1">{desc}</dd>
              </div>
            ))}
          </dl>
          <h3 className="text-lg font-medium text-[#1a2332] pt-2">False positives</h3>
          <p>
            Every run mixes in one or two scenarios that are benign activity tripping real
            detection rules — the calls that make Tier-1 work hard. Dismissing them correctly
            scores just like catching an attack; escalating them counts against you. Examples of
            what you'll see:
          </p>
          <ul className="list-disc list-inside space-y-1 text-sm">
            {FALSE_POSITIVES.map((fp) => (
              <li key={fp}>{fp}</li>
            ))}
          </ul>
          <h3 className="text-lg font-medium text-[#1a2332] pt-2">Triage review</h3>
          <p>
            After every resolved scenario you get a triage review: the mapped MITRE ATT&CK
            technique (ID, tactic, and a link to the framework), a plain-language explanation of
            the attack vector, and the SOC playbook steps a real team would run in response.
          </p>
        </Section>

        <Section id="analytics" title="Analytics">
          <p>Every classification you make lands in one of four buckets:</p>
          <ul className="list-disc list-inside space-y-1 text-sm">
            <li>
              <span className="text-[#1a2332] font-medium">Correct</span> — a real threat classified with the
              right category
            </li>
            <li>
              <span className="text-[#1a2332] font-medium">Missed</span> — a real threat given the wrong
              category
            </li>
            <li>
              <span className="text-[#1a2332] font-medium">FP Caught</span> — a false positive correctly
              dismissed
            </li>
            <li>
              <span className="text-[#1a2332] font-medium">FP Missed</span> — a false positive escalated as a
              threat
            </li>
          </ul>
          <p>
            Accuracy is <span className="font-mono text-sm text-[#1a2332]">(correct + FP caught) / total classifications</span>.
            The Analytics tab tracks it all: your report card, a results chart, a progress tracker
            for the ten scenarios in your queue, and a review of your recent decisions with
            feedback on each. Finish the queue and you get a final grade.
          </p>
        </Section>

        <Section id="reports" title="Reports">
          <p>
            Triage is only half the job — the other half is documentation. For each scenario you
            can file an incident report: what happened, who was affected, and what you did about
            it. Reports live in their own tab where you can edit them, track their status, and
            export them to PDF, the way you'd hand findings to a Tier-2 escalation or a manager.
          </p>
        </Section>

        {/* Bottom CTA */}
        <div className="mt-16 rounded-2xl bg-white border border-[#e2e6ea] p-8 text-center" style={{ boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
          <p className="text-xl text-[#1a2332] mb-4">Ready to take the queue?</p>
          <Link
            to="/sim"
            className="inline-block bg-[#101218] hover:bg-[#1e2330] text-white font-medium rounded-full px-8 py-3 transition-colors"
          >
            Launch Sim
          </Link>
        </div>
      </main>

      <footer className="border-t border-[#e2e6ea] py-6">
        <div className="max-w-3xl mx-auto px-6 flex items-center justify-between text-sm text-[#6e7781]">
          <span>&copy; 2026 Spectyr. All rights reserved.</span>
          <span>SOC Simulation Training</span>
        </div>
      </footer>
    </div>
  );
};

export default Docs;
