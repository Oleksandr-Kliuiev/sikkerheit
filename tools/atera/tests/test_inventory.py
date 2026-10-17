import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from inventory_snapshots import InvalidSnapshot, read_snapshot  # noqa: E402
from reconciliation import reconcile  # noqa: E402

NOW = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / 'examples/pilot-snapshot.json').read_text())

    def report(self):
        return reconcile(read_snapshot(self.document), NOW, '0.1.0')

    def first_device(self):
        return self.document['sikkerheit']['organizations'][0]['pages'][0]['items'][0]

    def test_name_match_is_only_a_candidate_inside_the_mapped_customer(self):
        report = self.report()
        unlinked = next(item for item in report['issues'] if item['kind'] == 'unlinked_agent')
        self.assertEqual(102, unlinked['agentId'])
        self.assertEqual(['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'], unlinked['nameCandidates'])
        self.assertFalse(unlinked['candidateIdentityConfirmed'])
        self.assertEqual(2, len(self.document['deviceMappings']))

    def test_cross_customer_device_mapping_is_rejected(self):
        self.document['deviceMappings'][0]['organizationId'] = self.document['customerMappings'][1]['organizationId']
        with self.assertRaisesRegex(InvalidSnapshot, 'crosses'):
            self.report()

    def test_duplicate_agents_and_duplicate_customer_mappings_are_rejected(self):
        for key, change in (
            ('agents', lambda: self.document['atera']['agents'].append(copy.deepcopy(self.document['atera']['agents'][0]))),
            ('customers', lambda: self.document['customerMappings'].append(copy.deepcopy(self.document['customerMappings'][0]))),
        ):
            with self.subTest(key=key):
                original = copy.deepcopy(self.document)
                change()
                with self.assertRaises(InvalidSnapshot):
                    self.report()
                self.document = original

    def test_incomplete_pages_never_prove_a_missing_installation(self):
        page = self.document['sikkerheit']['organizations'][0]['pages'][0]
        page['items'] = []
        page['nextCursor'] = 'next-page'
        report = self.report()
        self.assertFalse(report['comparisonComplete'])
        self.assertNotIn('mapped_device_missing', report['summary']['issuesByKind'])
        self.assertIn('coverage_unconfirmed', report['summary']['issuesByKind'])

    def test_full_cursor_chain_allows_an_absence_conclusion(self):
        page = self.document['sikkerheit']['organizations'][0]['pages'][0]
        page['items'] = []
        page['nextCursor'] = 'next-page'
        self.document['sikkerheit']['organizations'][0]['pages'].append({'cursor': 'next-page', 'items': [], 'nextCursor': None})
        self.assertIn('mapped_device_missing', self.report()['summary']['issuesByKind'])

    def test_stale_snapshot_or_missing_organization_never_proves_absence(self):
        self.document['sikkerheit']['capturedAt'] = '2026-10-01T12:00:00Z'
        self.document['sikkerheit']['organizations'][0]['pages'][0]['items'] = []
        report = self.report()
        self.assertFalse(report['comparisonComplete'])
        self.assertNotIn('mapped_device_missing', report['summary']['issuesByKind'])
        self.document['sikkerheit']['organizations'] = []
        self.assertNotIn('mapped_device_missing', self.report()['summary']['issuesByKind'])

    def test_last_seen_is_not_treated_as_confirmed_rmm_online_presence(self):
        issue = next(item for item in self.report()['issues'] if item['kind'] == 'last_seen_old')
        self.assertFalse(issue['rmmOnlinePresenceConfirmed'])
        self.assertEqual(201, issue['agentId'])

    def test_version_comparison_is_numeric_and_identity_conflicts_remain_visible(self):
        device = self.first_device()
        device['agentVersion'] = '0.10.0'
        device['identityState'] = 'identity_conflict'
        report = reconcile(read_snapshot(self.document), NOW, '0.2.0')
        self.assertTrue(any(item['kind'] == 'identity_conflict' and item['agentId'] == 101 for item in report['issues']))
        self.assertFalse(any(item['kind'] == 'version_below_minimum' and item['agentId'] == 101 for item in report['issues']))

    def test_revocation_is_not_silently_repaired(self):
        self.first_device()['status'] = 'revoked'
        issue = next(item for item in self.report()['issues'] if item['kind'] == 'revoked')
        self.assertEqual(101, issue['agentId'])
        self.assertNotIn('actions', issue)

    def test_repeated_cursor_or_a_missing_first_page_is_rejected(self):
        page = self.document['sikkerheit']['organizations'][0]['pages'][0]
        page['cursor'] = 'second-page'
        with self.assertRaises(InvalidSnapshot):
            self.report()
        page['cursor'] = None
        page['nextCursor'] = 'repeat'
        self.document['sikkerheit']['organizations'][0]['pages'].append({'cursor': 'repeat', 'items': [], 'nextCursor': 'repeat'})
        with self.assertRaises(InvalidSnapshot):
            self.report()

    def test_missing_atera_agent_is_unknown_for_an_incomplete_source(self):
        self.document['atera']['agents'] = self.document['atera']['agents'][1:]
        self.document['atera']['complete'] = False
        report = self.report()
        self.assertNotIn('mapped_atera_agent_missing', report['summary']['issuesByKind'])
        self.assertIn('coverage_unconfirmed', report['summary']['issuesByKind'])

    def test_boolean_ids_and_timestamps_without_timezone_are_rejected(self):
        self.document['atera']['agents'][0]['agentId'] = True
        with self.assertRaises(InvalidSnapshot):
            self.report()
        self.document['atera']['agents'][0]['agentId'] = 101
        self.document['atera']['capturedAt'] = '2026-10-17T12:00:00'
        with self.assertRaises(InvalidSnapshot):
            self.report()

    def test_cli_writes_a_private_report_without_copying_unknown_source_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            source, report = Path(directory) / 'source.json', Path(directory) / 'report.json'
            self.document['atera']['ignoredSecret'] = 'synthetic-secret-must-not-appear'
            source.write_text(json.dumps(self.document))
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'check_inventory.py'), '--input', str(source),
                '--report', str(report), '--as-of', NOW.isoformat(), '--minimum-agent-version', '0.1.0'], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(report.read_text())['comparisonComplete'])
            self.assertNotIn('synthetic-secret', report.read_text() + result.stdout + result.stderr)
            if os.name != 'nt':
                self.assertEqual(0o600, stat.S_IMODE(report.stat().st_mode))

    def test_cli_refuses_to_overwrite_the_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.json'
            content = json.dumps(self.document)
            source.write_text(content)
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'check_inventory.py'), '--input', str(source),
                '--report', str(source)], capture_output=True, text=True, check=False)
            self.assertEqual(1, result.returncode)
            self.assertEqual(content, source.read_text())

    def test_cli_refuses_a_report_hard_link_to_the_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source, report = Path(directory) / 'source.json', Path(directory) / 'report.json'
            content = json.dumps(self.document)
            source.write_text(content)
            os.link(source, report)
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'check_inventory.py'), '--input', str(source),
                '--report', str(report)], capture_output=True, text=True, check=False)
            self.assertEqual(1, result.returncode)
            self.assertEqual(content, source.read_text())


if __name__ == '__main__':
    unittest.main()
