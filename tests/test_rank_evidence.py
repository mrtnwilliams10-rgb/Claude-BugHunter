"""Evidence-aware ranking + Cloudflare-challenge detection.

Before this, `cbh surface` ranked purely on hostname keywords and never read the
HTTP probe — so a Cloudflare bot-wall (403 "Attention Required!") looked like live
app surface, a realtime websocket origin sank below a tracking pixel, and a CDN
host named `cdne`/`cdnl` dodged the kill-list because the hint matched `cdn.` with
a trailing dot. These lock in the fix: the probe tags the WAF wall, and the ranker
reads status/method/server off the probe record.
"""
import unittest
from unittest.mock import patch

from cbh import cli


class CloudflareChallengeDetectionTests(unittest.TestCase):
    def test_cf_attention_required_is_flagged_blocked(self):
        headers = {"server": "cloudflare"}
        body = "<title>Attention Required! | Cloudflare</title>"
        with patch.object(cli, "http_get", return_value=(403, headers, body)):
            rec = cli.recon_http_probe("www.example.test")
        self.assertTrue(rec["blocked"])
        self.assertEqual(rec["waf"], "cloudflare")

    def test_normal_200_is_not_blocked(self):
        headers = {"server": "nginx"}
        with patch.object(cli, "http_get", return_value=(200, headers, "<title>Home</title>")):
            rec = cli.recon_http_probe("app.example.test")
        self.assertFalse(rec["blocked"])
        self.assertEqual(rec["waf"], "")


class EvidenceRankingTests(unittest.TestCase):
    def test_websocket_origin_ranks_p1_not_p2(self):
        prio, why = cli._rank_asset(
            "websocket-v6-public-origin.example.test",
            {"code": 405, "server": "", "title": "", "blocked": False},
        )
        self.assertEqual(prio, "P1")
        self.assertIn("websocket", why.lower())

    def test_405_method_sensitive_host_ranks_p1(self):
        # A non-tracking method-gated host is a real backend → P1.
        prio, why = cli._rank_asset(
            "d.example.test",
            {"code": 405, "server": "", "title": "", "blocked": False},
        )
        self.assertEqual(prio, "P1")
        self.assertIn("405", why)

    def test_tracking_plumbing_demoted_even_when_405(self):
        # Pixels/trackers are method-gated too, but low yield — must not flood P1.
        for host in ("trk.account.example.test", "pxl.example.test"):
            with self.subTest(host=host):
                prio, why = cli._rank_asset(
                    host, {"code": 405, "server": "", "title": "", "blocked": False})
                self.assertEqual(prio, "P2")
                self.assertIn("tracking", why.lower())

    def test_cdn_with_trailing_letter_is_killed(self):
        # The old `startswith("cdn.")` missed these.
        for host in ("cdne.example.test", "cdnl.example.test"):
            with self.subTest(host=host):
                prio, why = cli._rank_asset(host, {"code": 403, "server": "cloudflare",
                                                   "title": "Attention Required!", "blocked": True})
                self.assertEqual(prio, "KILL")

    def test_cf_challenge_annotates_rationale_without_hiding_value(self):
        # A CF-walled app host keeps its standard-surface rank but is marked blind.
        prio, why = cli._rank_asset(
            "www.example.test",
            {"code": 403, "server": "cloudflare", "title": "Attention Required!", "blocked": True},
        )
        self.assertIn("browser pass", why.lower())

    def test_rank_host_backcompat_hostname_only(self):
        # Legacy hostname-only entrypoint still works (no probe record).
        prio, why = cli._rank_host("api.example.test")
        self.assertEqual(prio, "P1")


class EvidenceBugClassTests(unittest.TestCase):
    def test_build_manifest_tags_evidence_classes(self):
        live = [
            {"host": "websocket-v6-public-origin.example.test",
             "url": "http://websocket-v6-public-origin.example.test/",
             "code": 405, "server": "", "title": "", "blocked": False},
            {"host": "trk.account.example.test",
             "url": "http://trk.account.example.test/",
             "code": 405, "server": "", "title": "", "blocked": False},
        ]
        resolved = {r["host"]: ["203.0.113.1"] for r in live}
        m = cli.build_manifest("example.test", set(resolved), resolved, live)
        by_host = {r["host"]: r for r in m["ranked_surface"]}
        self.assertIn("hunt-websocket", by_host["websocket-v6-public-origin.example.test"]["bug_classes"])
        self.assertIn("hunt-api-misconfig", by_host["trk.account.example.test"]["bug_classes"])
        # Both are evidence-P1 — the inversion is gone.
        self.assertEqual(by_host["websocket-v6-public-origin.example.test"]["priority"], "P1")


if __name__ == "__main__":
    unittest.main()
