"""
Local smoke tests — no AWS credentials required.
boto3 calls are patched throughout.

Run:  python test_local.py
"""
import json
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Stub boto3 before any project module imports it
# ---------------------------------------------------------------------------
_boto3_stub = MagicMock()
sys.modules["boto3"] = _boto3_stub
sys.modules["botocore"] = MagicMock()
sys.modules["botocore.exceptions"] = MagicMock()

# Make ClientError importable
class _ClientError(Exception):
    pass
sys.modules["botocore.exceptions"].ClientError = _ClientError

# Env vars required at import time by s3_utils
import os
os.environ.setdefault("S3_BUCKET_NAME", "test-bucket")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-2:000000000000:test")

import rules
import tools
import playbooks
import agent  # imported here so @patch("agent.invoke") can resolve the target


# ---------------------------------------------------------------------------
# rules.normalize_time
# ---------------------------------------------------------------------------
class TestNormalizeTime(unittest.TestCase):
    def test_hhmm(self):
        self.assertEqual(rules.normalize_time("14:30"), 14)

    def test_hhmmss(self):
        self.assertEqual(rules.normalize_time("02:13:00"), 2)

    def test_12h_am(self):
        self.assertEqual(rules.normalize_time("02:13 AM"), 2)

    def test_12h_pm(self):
        self.assertEqual(rules.normalize_time("02:13 PM"), 14)

    def test_invalid(self):
        self.assertIsNone(rules.normalize_time("not-a-time"))

    def test_none(self):
        self.assertIsNone(rules.normalize_time(None))

    def test_empty(self):
        self.assertIsNone(rules.normalize_time(""))


# ---------------------------------------------------------------------------
# rules.score_log
# ---------------------------------------------------------------------------
class TestScoreLog(unittest.TestCase):
    def _log(self, **kwargs):
        base = {
            "user": "test", "event": "ConsoleLogin", "source_ip": "1.2.3.4",
            "time": "10:00", "_hour": 10, "success": True, "location": "USA",
            "mfa_used": True, "failed_attempts": 0,
        }
        base.update(kwargs)
        return base

    def test_clean_login_low_risk(self):
        score, reasons, blockers = rules.score_log(self._log())
        self.assertEqual(score, 0)
        self.assertEqual(blockers, [])

    def test_event_modifier_delete_trail(self):
        score, _, _ = rules.score_log(self._log(event="DeleteTrail"))
        self.assertGreaterEqual(score, 3)

    def test_brute_force(self):
        score, reasons, _ = rules.score_log(
            self._log(success=False, failed_attempts=5)
        )
        self.assertIn(2, [score])  # +2 for brute-force
        self.assertTrue(any("Brute force" in r for r in reasons))

    def test_unusual_location(self):
        score, reasons, _ = rules.score_log(self._log(location="Russia"))
        self.assertIn(2, [score - 0])  # location contributes +2
        self.assertTrue(any("Russia" in r for r in reasons))

    def test_mfa_false_adds_blocker_reason(self):
        _, reasons, blockers = rules.score_log(self._log(mfa_used=False))
        self.assertTrue(any("MFA not used" in r for r in reasons))
        self.assertNotIn("missing_field:mfa_used", blockers)

    def test_mfa_none_adds_blocker(self):
        _, reasons, blockers = rules.score_log(self._log(mfa_used=None))
        self.assertTrue(any("unknown" in r for r in reasons))
        self.assertIn("missing_field:mfa_used", blockers)

    def test_off_hours(self):
        score, reasons, _ = rules.score_log(self._log(_hour=3))
        self.assertTrue(any("Off-hours" in r for r in reasons))

    def test_missing_time_blocker(self):
        log = self._log(_hour=None)
        _, _, blockers = rules.score_log(log)
        self.assertIn("missing_field:time", blockers)

    def test_malicious_ip(self):
        score, reasons, _ = rules.score_log(self._log(source_ip="192.168.100.1"))
        self.assertTrue(any("malicious" in r for r in reasons))
        self.assertGreaterEqual(score, 3)

    def test_unknown_event_defaults_to_plus1(self):
        score, _, _ = rules.score_log(self._log(event="SomeWeirdEvent"))
        self.assertGreaterEqual(score, 1)


# ---------------------------------------------------------------------------
# rules.classify_severity
# ---------------------------------------------------------------------------
class TestClassifySeverity(unittest.TestCase):
    def test_low(self):
        self.assertEqual(rules.classify_severity(3), "LOW")

    def test_medium_lower(self):
        self.assertEqual(rules.classify_severity(4), "MEDIUM")

    def test_medium_upper(self):
        self.assertEqual(rules.classify_severity(6), "MEDIUM")

    def test_high(self):
        self.assertEqual(rules.classify_severity(7), "HIGH")

    def test_zero(self):
        self.assertEqual(rules.classify_severity(0), "LOW")


# ---------------------------------------------------------------------------
# tools.check_ip_reputation
# ---------------------------------------------------------------------------
class TestIPReputation(unittest.TestCase):
    def test_known_malicious(self):
        r = tools.check_ip_reputation("192.168.100.1")
        self.assertEqual(r["reputation"], "malicious")
        self.assertIsNotNone(r["category"])

    def test_unknown_ip(self):
        r = tools.check_ip_reputation("8.8.8.8")
        self.assertEqual(r["reputation"], "unknown")
        self.assertIsNone(r["category"])

    def test_empty_ip(self):
        r = tools.check_ip_reputation("")
        self.assertEqual(r["reputation"], "unknown")

    def test_all_malicious_stubs(self):
        for ip in ("192.168.100.1", "10.0.0.99", "203.0.113.5"):
            with self.subTest(ip=ip):
                self.assertEqual(tools.check_ip_reputation(ip)["reputation"], "malicious")


# ---------------------------------------------------------------------------
# playbooks
# ---------------------------------------------------------------------------
class TestPlaybooks(unittest.TestCase):
    def test_high_action(self):
        self.assertIn("SOC", playbooks.get_playbook_action("HIGH"))

    def test_medium_action(self):
        action = playbooks.get_playbook_action("MEDIUM")
        self.assertIn("security", action.lower())

    def test_low_action(self):
        action = playbooks.get_playbook_action("LOW")
        self.assertIn("monitor", action.lower())

    def test_unknown_severity_falls_back_to_low(self):
        self.assertEqual(
            playbooks.get_playbook_action("UNKNOWN"),
            playbooks.get_playbook_action("LOW"),
        )

    def test_get_playbook_has_steps(self):
        for sev in ("LOW", "MEDIUM", "HIGH"):
            pb = playbooks.get_playbook(sev)
            self.assertIn("steps", pb)
            self.assertGreater(len(pb["steps"]), 0)


# ---------------------------------------------------------------------------
# agent — mocked bedrock
# ---------------------------------------------------------------------------
_GOOD_RESPONSE = json.dumps({
    "confidence": 0.9,
    "confidence_blockers": [],
    "severity": "HIGH",
    "reasoning": "Multiple high-risk indicators.",
    "playbook_action": "Disable account and alert SOC",
    "escalate": True,
    "needs_enrichment": False,
})

_LOW_CONFIDENCE_RESPONSE = json.dumps({
    "confidence": 0.5,
    "confidence_blockers": ["ip_reputation_unknown"],
    "severity": "MEDIUM",
    "reasoning": "Insufficient data.",
    "playbook_action": "Monitor",
    "escalate": False,
    "needs_enrichment": True,
})


class TestAgent(unittest.TestCase):
    def _base_log(self):
        return {
            "user": "alice", "event": "ConsoleLogin", "source_ip": "8.8.8.8",
            "time": "02:00", "_hour": 2, "success": False, "location": "Russia",
            "mfa_used": False, "failed_attempts": 5,
        }

    @patch("agent.invoke", return_value=_GOOD_RESPONSE)
    def test_high_severity_result(self, _mock):
        # Uses malicious IP so ip_reputation resolves — no force-iteration blocker
        log = self._base_log()
        log["source_ip"] = "192.168.100.1"
        result = agent.run_agent(log, risk_score=9, reasons=["test"], rules_blockers=[])
        self.assertEqual(result["severity"], "HIGH")
        self.assertTrue(result["escalate"])
        self.assertEqual(result["iterations"], 1)
        self.assertFalse(result["capped"])

    @patch("agent.invoke", return_value=_GOOD_RESPONSE)
    def test_result_has_required_keys(self, _mock):
        result = agent.run_agent(self._base_log(), risk_score=5, reasons=[], rules_blockers=[])
        for key in ("severity", "confidence", "reasoning", "playbook_action", "escalate", "iterations", "capped", "enrichment"):
            self.assertIn(key, result)

    @patch("agent.invoke", return_value=_GOOD_RESPONSE)
    def test_malicious_ip_enriched(self, _mock):
        log = self._base_log()
        log["source_ip"] = "192.168.100.1"
        result = agent.run_agent(log, risk_score=10, reasons=[], rules_blockers=[])
        self.assertEqual(result["enrichment"]["ip_reputation"], "malicious")

    @patch("agent.invoke", return_value=_GOOD_RESPONSE)
    def test_unknown_ip_force_iterates_to_cap(self, _mock):
        # 8.8.8.8 is unknown → ip_reputation_unknown → force-blocker → cap at 3
        result = agent.run_agent(self._base_log(), risk_score=5, reasons=[], rules_blockers=[])
        self.assertIn("ip_reputation_unknown", result["confidence_blockers"])
        self.assertTrue(result["capped"])
        self.assertEqual(result["iterations"], agent.MAX_ITERATIONS)

    @patch("agent.invoke", return_value=_LOW_CONFIDENCE_RESPONSE)
    def test_iteration_cap_sets_capped_flag(self, _mock):
        # Low confidence + force-iteration blocker on every pass → hits cap
        result = agent.run_agent(self._base_log(), risk_score=5, reasons=[], rules_blockers=[])
        self.assertTrue(result["capped"])
        self.assertEqual(result["iterations"], agent.MAX_ITERATIONS)

    @patch("agent.invoke", side_effect=Exception("boom"))
    def test_bedrock_error_propagates(self, _mock):
        with self.assertRaises(Exception):
            agent.run_agent(self._base_log(), risk_score=5, reasons=[], rules_blockers=[])


# ---------------------------------------------------------------------------
# main — validation & normalisation (CloudTrail schema)
# ---------------------------------------------------------------------------
import main as _main

def _ct_log(**kwargs):
    """Minimal valid CloudTrail event; keyword args override defaults."""
    base = {
        "eventTime":       "2024-01-15T10:00:00Z",
        "eventName":       "ConsoleLogin",
        "sourceIPAddress": "1.2.3.4",
        "userIdentity":    {"type": "IAMUser", "userName": "alice"},
        "additionalEventData": {"MFAUsed": "Yes"},
        "responseElements": {"ConsoleLogin": "Success"},
    }
    base.update(kwargs)
    return base


class TestMainValidation(unittest.TestCase):
    def test_valid_cloudtrail_log_passes(self):
        self.assertTrue(_main._validate(_ct_log(), "evt-001"))

    def test_missing_eventTime_fails(self):
        log = _ct_log()
        del log["eventTime"]
        self.assertFalse(_main._validate(log, "evt-002"))

    def test_missing_userIdentity_fails(self):
        log = _ct_log()
        del log["userIdentity"]
        self.assertFalse(_main._validate(log, "evt-003"))

    def test_normalise_extracts_user_from_iam_user(self):
        result = _main._normalise(_ct_log())
        self.assertEqual(result["user"], "alice")

    def test_normalise_extracts_user_from_assumed_role(self):
        log = _ct_log(userIdentity={
            "type": "AssumedRole",
            "principalId": "AROA:session",
            "sessionContext": {"sessionIssuer": {"userName": "bob"}},
        })
        result = _main._normalise(log)
        self.assertEqual(result["user"], "bob")

    def test_normalise_mfa_from_console_login(self):
        result = _main._normalise(_ct_log(additionalEventData={"MFAUsed": "No"}))
        self.assertFalse(result["mfa_used"])

    def test_normalise_mfa_from_session_context(self):
        log = _ct_log()
        log["userIdentity"] = {
            "type": "IAMUser", "userName": "carol",
            "sessionContext": {"attributes": {"mfaAuthenticated": "true"}},
        }
        del log["additionalEventData"]
        result = _main._normalise(log)
        self.assertTrue(result["mfa_used"])

    def test_normalise_mfa_unknown_when_absent(self):
        log = _ct_log()
        del log["additionalEventData"]
        result = _main._normalise(log)
        self.assertIsNone(result["mfa_used"])

    def test_normalise_success_from_console_login(self):
        result = _main._normalise(_ct_log(responseElements={"ConsoleLogin": "Failure"}))
        self.assertFalse(result["success"])

    def test_normalise_failure_from_error_code(self):
        log = _ct_log(errorCode="AccessDenied")
        del log["responseElements"]
        result = _main._normalise(log)
        self.assertFalse(result["success"])

    def test_normalise_null_response_elements(self):
        result = _main._normalise(_ct_log(responseElements=None))
        self.assertTrue(result["success"])

    def test_normalise_iso_time_parsed_to_hour(self):
        result = _main._normalise(_ct_log(eventTime="2024-01-15T14:30:00Z"))
        self.assertEqual(result["_hour"], 14)

    def test_normalise_bad_time_gives_none_hour(self):
        result = _main._normalise(_ct_log(eventTime="not-a-timestamp"))
        self.assertIsNone(result["_hour"])

    def test_normalise_location_always_unknown(self):
        result = _main._normalise(_ct_log())
        self.assertEqual(result["location"], "Unknown")

    def test_normalise_preserves_original_cloudtrail_fields(self):
        result = _main._normalise(_ct_log())
        self.assertIn("eventName", result)
        self.assertIn("userIdentity", result)


# ---------------------------------------------------------------------------
# main — run() with zero events
# ---------------------------------------------------------------------------
class TestRunEmpty(unittest.TestCase):
    @patch("main.fetch_events", return_value=[])
    @patch("main.classify_risk")
    @patch("agent.invoke")
    def test_zero_events_returns_empty_report(self, _inv, _lex, _fetch):
        report = _main.run()
        self.assertEqual(report["logs_processed"], 0)
        self.assertEqual(report["logs_failed"], 0)
        self.assertEqual(report["results"], [])
        self.assertIn("run_timestamp", report)

    @patch("main.fetch_events", return_value=[])
    @patch("main._send_alert")
    def test_zero_events_no_alert_sent(self, mock_alert, _fetch):
        _main.run()
        mock_alert.assert_not_called()

    @patch("main.fetch_events", side_effect=__import__("cloudtrail_client").CloudTrailFetchError("network error"))
    def test_fetch_error_returns_error_report(self, _fetch):
        report = _main.run()
        self.assertIn("error", report)
        self.assertEqual(report["logs_processed"], 0)


# ---------------------------------------------------------------------------
# Integration: normalise + score all entries from logs.py
# ---------------------------------------------------------------------------
class TestLogsDataset(unittest.TestCase):
    def _normalised(self, raw):
        return _main._normalise(dict(raw))

    def test_all_logs_score_without_error(self):
        import logs
        for entry in logs.LOGS:
            log = self._normalised(entry)
            with self.subTest(user=log.get("user"), event=log.get("event")):
                score, reasons, blockers = rules.score_log(log)
                severity = rules.classify_severity(score)
                self.assertIn(severity, ("LOW", "MEDIUM", "HIGH"))
                self.assertIsInstance(reasons, list)
                self.assertIsInstance(blockers, list)

    def test_alice_rules_score_is_medium(self):
        # Rules score is MEDIUM because failed_attempts requires cross-event aggregation
        # and location requires GeoIP — both are unavailable from a single CloudTrail event.
        # Lex intent (HighRiskEvent) is what drives the HIGH classification end-to-end.
        import logs
        raw = next(l for l in logs.LOGS
                   if l.get("userIdentity", {}).get("userName") == "alice"
                   and l.get("eventName") == "ConsoleLogin")
        log = self._normalised(raw)
        score, _, _ = rules.score_log(log)
        self.assertEqual(rules.classify_severity(score), "MEDIUM")

    def test_bob_is_low_severity(self):
        import logs
        raw = next(l for l in logs.LOGS
                   if l.get("userIdentity", {}).get("userName") == "bob")
        log = self._normalised(raw)
        score, _, _ = rules.score_log(log)
        self.assertEqual(rules.classify_severity(score), "LOW")

    def test_grace_delete_trail_is_high(self):
        # Grace uses AssumedRole — userName is in sessionContext.sessionIssuer
        import logs
        raw = next(l for l in logs.LOGS if l.get("eventName") == "DeleteTrail")
        log = self._normalised(raw)
        score, _, _ = rules.score_log(log)
        self.assertEqual(rules.classify_severity(score), "HIGH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
