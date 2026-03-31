import json
import logging

from bedrock_client import invoke, BedrockResponseError
from tools import check_ip_reputation
from playbooks import get_playbook_action

MAX_ITERATIONS = 3
CONFIDENCE_THRESHOLD = 0.8

# Blockers that force another iteration (not just reduce score)
_FORCE_ITERATION_BLOCKERS = frozenset({"ip_reputation_unknown", "enrichment_lambda_failed"})

_SYSTEM_PROMPT = """\
You are a security analyst AI. Your job is to assess IAM log events and produce \
structured triage reports.

You must respond with valid JSON only — no preamble, no markdown fences, no extra text.

Output schema:
{
  "confidence": <float 0.0–1.0>,
  "confidence_blockers": ["<string>", ...],
  "severity": "LOW|MEDIUM|HIGH",
  "reasoning": "<string>",
  "playbook_action": "<string>",
  "escalate": true|false,
  "needs_enrichment": true|false
}

Field guidance:
- confidence: your certainty in this assessment (1.0 = fully certain)
- confidence_blockers: specific gaps that limit certainty, e.g. "unknown IP reputation"
- severity: based on the risk indicators present
- escalate: true when severity is HIGH or there are strong compromise indicators
- needs_enrichment: true if additional GeoIP or behavior baseline data would \
materially change the assessment

Note: enrichment data from the Lambda tool is simulated for this environment \
and should be treated as supporting context only, not primary evidence for \
escalation decisions.\
"""


def _compute_confidence(llm_score, blockers):
    """Take the lower of the LLM-reported score and the blocker-penalised score."""
    if not blockers:
        return llm_score
    computed = 0.8 - (0.1 * len(blockers))
    return min(llm_score, max(computed, 0.0))


def _should_continue(confidence, blockers, iteration):
    """Return True if the loop should run another iteration."""
    if iteration >= MAX_ITERATIONS:
        return False
    if any(b in _FORCE_ITERATION_BLOCKERS for b in blockers):
        return True
    return confidence < CONFIDENCE_THRESHOLD


def _build_user_message(log, enrichment, history, risk_score, reasons):
    parts = [
        "Log entry:",
        json.dumps(log, indent=2),
        f"\nRule-based risk score: {risk_score}",
        f"Rule-based reasons: {json.dumps(reasons)}",
    ]
    if enrichment:
        parts.append(f"\nEnrichment data:\n{json.dumps(enrichment, indent=2)}")
    if history:
        parts.append(f"\nIteration history:\n{json.dumps(history, indent=2)}")
    return "\n".join(parts)


def run_agent(log, enrichment_data=None, risk_score=None, reasons=None, rules_blockers=None):
    """
    Run the enrich → reason agentic loop for a single log entry.

    Args:
        log:            Validated, normalised log dict (must include _hour if available).
        enrichment_data: Optional pre-fetched enrichment dict (e.g. from enrichment Lambda).
        risk_score:     Pre-computed score from rules.py.
        reasons:        Pre-computed reason strings from rules.py.
        rules_blockers: Pre-computed blocker strings from rules.py.

    Returns:
        result dict matching the report entry schema.

    Raises:
        BedrockResponseError | json.JSONDecodeError on unrecoverable agent failure.
    """
    enrichment = dict(enrichment_data) if enrichment_data else {}
    blockers = list(rules_blockers or [])
    iteration_history = []

    # --- IP reputation check (tool call) ---
    ip = log.get("source_ip", "")
    ip_rep = check_ip_reputation(ip)
    if ip_rep["reputation"] == "unknown":
        blockers.append("ip_reputation_unknown")
    elif ip_rep["reputation"] == "malicious":
        enrichment["ip_reputation"] = ip_rep

    last_result = None

    for iteration in range(1, MAX_ITERATIONS + 1):
        user_message = _build_user_message(log, enrichment, iteration_history, risk_score, reasons)

        try:
            raw = invoke(user_message, _SYSTEM_PROMPT)
            last_result = json.loads(raw)
        except json.JSONDecodeError as e:
            logging.error(f"Agent iteration {iteration}: LLM returned non-JSON: {e}")
            raise
        except BedrockResponseError:
            logging.error(f"Agent iteration {iteration}: Bedrock invocation failed")
            raise

        llm_confidence = float(last_result.get("confidence", 0.0))
        llm_blockers   = last_result.get("confidence_blockers", [])

        # Merge rules-level blockers with agent-reported blockers (deduplicate)
        all_blockers = list(dict.fromkeys(blockers + llm_blockers))

        final_confidence = _compute_confidence(llm_confidence, all_blockers)
        severity = last_result.get("severity", "LOW")

        history_entry = {
            "iteration":           iteration,
            "confidence":          final_confidence,
            "confidence_blockers": all_blockers,
            "severity":            severity,
            "needs_enrichment":    last_result.get("needs_enrichment", False),
        }
        iteration_history.append(history_entry)

        capped = iteration >= MAX_ITERATIONS

        if not _should_continue(final_confidence, all_blockers, iteration):
            return _build_result(last_result, final_confidence, all_blockers, ip_rep, iteration, capped=capped)

        # Resolve ip_reputation_unknown if enrichment was fetched in this pass
        # (In a real system this is where the enrichment Lambda would be called)
        if "ip_reputation_unknown" in blockers and enrichment.get("ip_reputation"):
            blockers = [b for b in blockers if b != "ip_reputation_unknown"]

        logging.info(f"Agent iteration {iteration} confidence={final_confidence:.2f}, continuing")

    # Loop exhausted — return capped result
    last_history = iteration_history[-1]
    return _build_result(
        last_result,
        last_history["confidence"],
        last_history["confidence_blockers"],
        ip_rep,
        MAX_ITERATIONS,
        capped=True,
    )


def _build_result(llm_result, confidence, blockers, ip_rep, iterations, capped):
    severity = llm_result.get("severity", "LOW")
    return {
        "severity":           severity,
        "confidence":         confidence,
        "confidence_blockers": blockers,
        "reasoning":          llm_result.get("reasoning", ""),
        "playbook_action":    llm_result.get("playbook_action") or get_playbook_action(severity),
        "escalate":           llm_result.get("escalate", False),
        "iterations":         iterations,
        "capped":             capped,
        "enrichment": {
            "ip_reputation": ip_rep["reputation"],
            "context_gaps":  [b for b in blockers if b.startswith("missing_field:")],
        },
    }
