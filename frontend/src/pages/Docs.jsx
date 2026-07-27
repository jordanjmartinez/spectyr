import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import BrandLockup from '../components/BrandLockup';

// Final visual-polish pass (Docs correction): the documentation describes
// the CURRENT product only -- Guided/Hardcore, the single-incident
// investigation loop across Detections / SIEM / Endpoints / Response, the
// submission boundary, and the Learning Review. The retired model (queue
// mechanics, Analytics destination, pre-submit reveals) is gone. The
// standing copy guards apply: no em dashes, no "SOC Queue", no
// report-workflow vocabulary, and the old product name never renders.
const SECTIONS = [
  { id: 'getting-started', label: 'Getting Started' },
  { id: 'how-spectr-works', label: 'How Spectr Works' },
  { id: 'guided-and-hardcore', label: 'Guided and Hardcore' },
  { id: 'detections', label: 'Detections' },
  { id: 'siem', label: 'SIEM' },
  { id: 'endpoints', label: 'Endpoints' },
  { id: 'response', label: 'Response' },
  { id: 'learning-review', label: 'Learning Review' },
];

const Section = ({ id, title, children }) => (
  <section id={id} className="scroll-mt-24 mt-16">
    <h2 className="text-2xl font-medium text-[#1a2332] mb-5">{title}</h2>
    <div className="space-y-4 text-[#57606a] text-base leading-relaxed">{children}</div>
  </section>
);

const Docs = () => {
  const [active, setActive] = useState('getting-started');

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

  // Honor a hash arriving from the landing (/docs#siem etc.)
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
      {/* VC3: the shared full-size BrandLockup (same component and size
          as the app shell -- no smaller Docs variant). VD6: the bar is
          the same fixed 68px shell row as the primary app (no
          shell-specific height differences). */}
      <div className="lg:hidden sticky top-0 z-20 h-[68px] flex items-center justify-between px-4 bg-[#101218] border-b border-white/10 text-white">
        <Link to="/" className="flex items-center">
          {/* VC4: below 480px the bar cannot hold the ghost, the
              wordmark, and the action; the wordmark yields (the ghost
              is retained), same reduction rule as the sim icon rail */}
          <BrandLockup wordmarkClass="hidden min-[480px]:inline" />
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
        {/* VC3: the aside's horizontal padding moves off the shell so the
            lockup row can run tighter (padding reduced first, logo
            dimensions preserved); nav and the action keep the original
            px-8 inset. VD6: the brand cell is the same fixed 68px shell
            row as the sim rail, flush at the top (the aside's former top
            padding is removed first, per the ruling), lockup centered. */}
        <aside className="hidden lg:flex flex-col shrink-0 w-72 sticky top-0 h-screen bg-[#101218] text-white pb-12">
          <Link to="/" className="flex items-center h-[68px] mb-12 px-4">
            <BrandLockup />
          </Link>

          <nav className="flex flex-col gap-2 px-8">
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
            className="liquid-btn mt-auto inline-flex items-center justify-center gap-2 rounded-full mx-8 px-5 py-2 text-sm font-medium text-white"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z" /></svg>
            Start Sim
          </Link>
        </aside>

        {/* Content */}
        <main className="flex-1 min-w-0 px-6 sm:px-10 lg:px-20 py-14 lg:py-24">
          <div className="max-w-2xl">
            <h1 className="text-5xl sm:text-6xl font-light tracking-tight text-[#1a2332] mb-8">
              Spectr
            </h1>
            <div className="space-y-4 text-[#57606a] text-lg leading-relaxed">
              <p>
                Spectr is a SOC investigation simulator. Choose Guided or Hardcore, investigate a
                single incident across Detections, SIEM, Endpoints, and Response, select your
                classification, submit your decision, and review your performance in Learning
                Review.
              </p>
            </div>

            <Section id="getting-started" title="Getting Started">
              <p>
                Press Start and choose your experience. Guided lets you pick a scenario from the
                catalog, or take a random one. Hardcore begins a timed run.
              </p>
              <p>
                The incident appears in the Incidents workspace with a short briefing. Select it to
                begin: triage, evidence searches, and response all run in the context of the
                incident you are working.
              </p>
              <p>
                The sidebar moves between workspaces: Dashboard, Incidents, SIEM, Detections,
                Endpoints, Response, and Metrics. Keys <span className="log-mono">1</span> through{' '}
                <span className="log-mono">7</span> switch between them.
              </p>
            </Section>

            <Section id="how-spectr-works" title="How Spectr Works">
              <p>Every incident moves through the same loop:</p>
              <ol className="list-decimal pl-5 space-y-2">
                <li>Choose Guided or Hardcore.</li>
                <li>Open the incident in the Incidents workspace and read its briefing.</li>
                <li>Triage from Detections: promote what is actionable, dismiss what is not.</li>
                <li>Investigate the evidence in the SIEM and follow entity clues.</li>
                <li>Inspect affected systems and accounts in Endpoints.</li>
                <li>Execute approved response actions in Response.</li>
                <li>Select your classification on the incident, then submit your decision.</li>
                <li>Review the result in the Learning Review under Metrics.</li>
              </ol>
              <p>
                Grading is disclosed only after you submit. Until then, nothing reveals whether a
                call is right, and the incident&apos;s ATT&amp;CK profile stays locked.
              </p>
            </Section>

            <Section id="guided-and-hardcore" title="Guided and Hardcore">
              <div>
                <p className="text-[#1a2332] font-medium mb-1">Guided</p>
                <p>
                  Pick one scenario from the catalog, or take a random one. There is no timer, and
                  optional hints are available while you investigate. After you submit, review the
                  incident and practice another scenario.
                </p>
              </div>
              <div>
                <p className="text-[#1a2332] font-medium mb-1">Hardcore</p>
                <p>
                  A timed run under a single 15-minute clock. Incidents are pushed to you during
                  the run and you investigate without hints. One wrong classification or an expired
                  timer ends the run.
                </p>
              </div>
              <p>
                Triage, evidence, readiness, and grading work identically in both modes. The
                difference is time pressure and guidance.
              </p>
            </Section>

            <Section id="detections" title="Detections">
              <p>
                Detections is where triage happens, and only triage. Review each detection and
                decide: Promote what looks actionable, Dismiss what does not hold up. A reviewed
                detection can be reopened if you change your mind.
              </p>
              <p>
                The Feed shows every detection, including reviewed ones. Threats shows the
                detections you promoted.
              </p>
              <p>
                Promoting never executes anything. It marks the detection as actionable and carries
                its context into the Response workspace.
              </p>
              <p>
                An incident can be submitted only after every one of its detections has been
                reviewed.
              </p>
            </Section>

            <Section id="siem" title="SIEM">
              <p>
                The SIEM is the investigation workbench over the incident&apos;s evidence. With an
                incident selected, searches run over that incident&apos;s events, and Investigate
                in SIEM on an incident or detection opens the workbench with that evidence already
                searched.
              </p>
              <p>Queries are written in LCQL, four segments joined by pipes:</p>
              <p className="log-mono text-[#1a2332]">TIMEFRAME | SENSOR | EVENT TYPE | FILTERS</p>
              <p>
                Run Query executes the bar as a frozen snapshot: results never move until you run
                again. When new matching telemetry arrives, a count appears with a Load new events
                action that brings the snapshot up to date.
              </p>
              <p>
                Sidebar values and per-field inspector actions refine the executed query. Entity
                pivots (host, account, IP, domain, process, file, event type, sensor) follow the
                clue across the evidence you are searching.
              </p>
              <p>
                Simple search accepts a single filter expression. Advanced LCQL accepts the
                complete four-part query.
              </p>
              <p>
                Quoting rules for filter values: values containing spaces or any of{' '}
                <span className="log-mono">&quot; &#39; = ! | *</span> must be quoted, and the bare
                words and, or, not, contains must be quoted to match literally. Double-quoted and
                unquoted values match case-insensitively; single quotes match exactly.
              </p>
            </Section>

            <Section id="endpoints" title="Endpoints">
              <p>
                Endpoints is investigation only. Each managed host has a snapshot you can inspect:
                Overview, Processes, Network, Services, Users, and Autoruns.
              </p>
              <p>
                Hostname values in event views pivot to the endpoint page, so you can move from a
                log line to the machine it happened on.
              </p>
              <p>
                Nothing executes here. When a host or process needs action, the Respond controls
                navigate to the Response workspace with the target selected.
              </p>
            </Section>

            <Section id="response" title="Response">
              <p>
                Response is the command surface where actions execute. Incident entities are
                grouped by target type: hosts, processes, files, accounts, and persistence.
              </p>
              <p>
                The available actions are Isolate Host, Release Host, Kill Process, Delete File,
                Disable Account, Revoke Sessions, Force Password Reset, and Remove Persistence.
                Every action asks for confirmation and is recorded in the Response Log.
              </p>
              <p>
                Actions change the current state of the environment, never the recorded evidence.
                The SIEM and the detection history always show what happened.
              </p>
              <p>
                When your response is complete, return to the incident to classify it: a threat
                with its attack category, or a false positive. Submit unlocks once every detection
                is reviewed and a classification is selected.
              </p>
            </Section>

            <Section id="learning-review" title="Learning Review">
              <p>
                Metrics is the Learning Review. After you submit an incident, its grade unlocks:
                the Incident Grade combines your classification call, your detection decisions,
                and your response actions.
              </p>
              <p>
                The review walks through your detection calls, required actions completed or
                missed, and any unnecessary or harmful actions, alongside the incident&apos;s
                ATT&amp;CK techniques and a response playbook.
              </p>
              <p>
                Session performance aggregates across the incidents you have submitted. It is
                labelled separately from the Incident Grade: one incident, one grade.
              </p>
            </Section>

          </div>
        </main>
      </div>
    </div>
  );
};

export default Docs;
