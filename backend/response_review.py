"""Stage 5 Phase 5 (workstream 5.1): the response-review reason-code
registry and the Tier 1 generic rationale templates.

Contract 7.1 (locked): every teaching entry carries exactly one bucket and
one stable reason_code; the registry below is the BINDING set -- additions
are contract amendments. Contract 7.3 + ratified OD-1/OD-3/OD-4 with review
correction 4: a generic template explains the ACTION'S PURPOSE only and may
never assert scenario-specific facts (scenario causality lives ONLY in the
Tier 2 paragraph); the two contract examples below are canonical copy,
byte-preserved. Pure module: no Flask, no session state, no clock.
"""
import action_overlay

# --- the 7.1 reason-code registry (binding set) ------------------------------

REQUIRED_COMPLETED = "required_completed"
REQUIRED_NOT_ATTEMPTED = "required_not_attempted"
REQUIRED_ATTEMPT_FAILED = "required_attempt_failed"
OUT_OF_ORDER = "out_of_order"
RELEASED_AFTER_ISOLATION = "released_after_isolation"
ACCEPTABLE_COMPLETED = "acceptable_completed"
COLLATERAL_IN_SCOPE = "collateral_in_scope"
INACTION_CORRECT = "inaction_correct"
INACTION_SPOILED = "inaction_spoiled"
# attempt-history-only codes (never a teaching bucket)
FAILED_PRECONDITION = "failed_precondition"
NO_EFFECT_REPEAT = "no_effect_repeat"

BUCKET_OF = {
    REQUIRED_COMPLETED: "completed",
    REQUIRED_NOT_ATTEMPTED: "missed",
    REQUIRED_ATTEMPT_FAILED: "missed",
    OUT_OF_ORDER: "missed",
    RELEASED_AFTER_ISOLATION: "missed",
    ACCEPTABLE_COMPLETED: "acceptable",
    COLLATERAL_IN_SCOPE: "collateral",
    INACTION_CORRECT: "inaction",
    INACTION_SPOILED: "inaction",
}

# --- Tier 1 templates (purpose-only; ~10 total, per (verb, code class)) ------

_PURPOSE = {
    "isolate_host": "Isolating an implicated host cuts an attacker's access to it while the investigation continues.",
    "kill_process": "Killing a malicious process stops its activity on the host immediately.",
    "delete_file": "Deleting a dropped file removes the attacker's tooling from the host.",
    "disable_account": "Disabling a compromised account blocks any further use of its credentials.",
    "revoke_sessions": "Revoking sessions ends active access held with stolen tokens or cookies.",
    "force_password_reset": "Forcing a password reset invalidates credentials the attacker may hold.",
    "remove_persistence": "Removing persistence prevents an attacker's foothold from surviving a restart.",
}

# (noun, the action noun, the past participle) per verb, for the frames.
_NOUN = {
    "isolate_host": ("host", "isolation", "isolated"),
    "kill_process": ("process", "termination", "terminated"),
    "delete_file": ("file", "deletion", "deleted"),
    "disable_account": ("account", "disabling", "disabled"),
    "revoke_sessions": ("account", "session revocation", "revoked"),
    "force_password_reset": ("account", "a password reset", "reset"),
    "remove_persistence": ("persistence entry", "removal", "removed"),
}

# Canonical contract copy (7.3 examples + 7.1 empty-state strings),
# byte-preserved.
COLLATERAL_WHY = ("This action was not part of the expected response for "
                  "this incident. Acting on targets the evidence does not "
                  "implicate disrupts clean assets.")
INACTION_CORRECT_WHY = ("No response action was required. The correct "
                        "response here was investigation without action.")
INACTION_SPOILED_WHY = ("No response action was required here, and action "
                        "was taken against this incident's assets; the "
                        "collateral entries carry what was done.")
RELEASED_WHY = ("Isolation only counts while it holds: this host was "
                "isolated but released before submission, so containment "
                "was not in effect when it mattered.")


def render_why(reason_code, action):
    """The frozen Tier 1 rationale text for one teaching entry. PURPOSE-ONLY
    by construction: composed from the verb's purpose sentence and a generic
    frame; no scenario token, hostname, account, or path ever enters
    (template-purity test enforced). Deterministic."""
    purpose = _PURPOSE.get(action, "")
    noun, action_noun, past = _NOUN.get(action, ("target", "action", "handled"))
    if reason_code == REQUIRED_COMPLETED:
        return f"{purpose} This {noun} was {past} before submission."
    if reason_code == REQUIRED_NOT_ATTEMPTED:
        return (f"{purpose} This {noun} required {action_noun} and was not "
                f"{past} at submission.")
    if reason_code == REQUIRED_ATTEMPT_FAILED:
        return (f"{purpose} Attempts were made but none succeeded, so this "
                f"{noun} was not {past} at submission.")
    if reason_code == OUT_OF_ORDER:
        return (f"{purpose} This step succeeded, but not before the step "
                f"that depended on it; the declared order was not met.")
    if reason_code == RELEASED_AFTER_ISOLATION:
        return RELEASED_WHY
    if reason_code == ACCEPTABLE_COMPLETED:
        return ("A defensible additional step, not part of the required "
                f"response. {purpose}")
    if reason_code == COLLATERAL_IN_SCOPE:
        return COLLATERAL_WHY
    if reason_code == INACTION_CORRECT:
        return INACTION_CORRECT_WHY
    if reason_code == INACTION_SPOILED:
        return INACTION_SPOILED_WHY
    raise ValueError(f"unknown reason code {reason_code!r}")


# --- expected-target display labels ------------------------------------------

def expected_label(action, target, registry):
    """Display label for a (possibly never-executed) expected composite, in
    the registry's own display grammar: resolve the composite to its
    registry entity (achievability guarantees required targets exist in the
    initial world) and reuse action_overlay.target_label; fall back to
    composing from the composite in the same grammar (scaffold decision,
    ratified: registry lookup with composite fallback)."""
    for e in registry.values():
        k = e.get("kind")
        if action in ("isolate_host", "release_host") and k == "host" \
                and e.get("hostname") == target.get("hostname"):
            return action_overlay.target_label(e)
        if action == "kill_process" and k == "process" \
                and e.get("hostname") == target.get("hostname") \
                and e.get("pid") == target.get("pid"):
            return action_overlay.target_label(e)
        if action == "delete_file" and k == "file" \
                and e.get("hostname") == target.get("hostname") \
                and e.get("path") == target.get("path"):
            return action_overlay.target_label(e)
        if action == "remove_persistence" and k == "persistence" \
                and tuple(e.get("identity") or ()) == tuple(target.get("identity") or ()):
            return action_overlay.target_label(e)
        if action in ("disable_account", "revoke_sessions",
                      "force_password_reset") and k == "account" \
                and action_overlay.account_key(e.get("domain"), e.get("username")) \
                == action_overlay.account_key(target.get("domain"), target.get("username")):
            return action_overlay.target_label(e)
    # composite fallback, same grammar
    if action in ("isolate_host", "release_host"):
        return target.get("hostname", "")
    if action == "kill_process":
        return f"PID {target.get('pid')} on {target.get('hostname')}"
    if action == "delete_file":
        return f"{target.get('display') or target.get('path')} on {target.get('hostname')}"
    if action == "remove_persistence":
        return f"persistence entry on {target.get('hostname', '')}"
    dom, user = target.get("domain"), target.get("username")
    return f"{dom}\\{user}" if dom else (user or "")


def expected_ref(action, target_key):
    """The stable expected-action identity string: the answer key's
    (action, composite target) pair, loader-unique per scenario."""
    return f"{action}:" + "/".join(str(p) for p in target_key)
