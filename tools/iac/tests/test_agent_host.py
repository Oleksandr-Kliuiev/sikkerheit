"""Preparing DNS does not bind it; applying TLS does not silently enable agent routes or change secrets."""
from script_harness import ScriptCase, rule


class AgentHostTests(ScriptCase):
    def run_host(self, mode='--plan', host='agent.example.no', extra=()):
        return self.run_script('configure-agent-host.sh', 'test', host, mode, rules=[*extra,
            rule(r'^webapp list ', out='app-sikkerheit-test-12345'),
            rule(r'^webapp show .*defaultHostName', out='app.azurewebsites.net'),
            rule(r'^webapp show .*customDomainVerificationId', out='verification'),
            rule(r'^webapp config ssl list ', out='existing-thumb')])

    def test_plan_only_reads_azure_and_prints_the_dns_records(self):
        result = self.run_host()
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertIn('CNAME agent.example.no', result.stdout)
        self.assertTrue(all(self.verb(call) in ('list', 'show') for call in self.az_calls()))

    def test_apply_reuses_a_certificate_and_does_not_change_app_settings(self):
        result = self.run_host('--apply')
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.calls_matching('config ssl create'), [])
        self.assertEqual(len(self.calls_matching('config ssl bind')), 1)
        self.assertEqual(self.calls_matching('config appsettings'), [])

    def test_new_certificate_is_polled_before_binding(self):
        result = self.run_host('--apply', extra=[rule(r'^webapp config ssl list ', outs=['', '', 'new-thumb'])])
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(len(self.calls_matching('config ssl create')), 1)
        self.assertIn('--certificate-thumbprint new-thumb', self.calls_matching('config ssl bind')[0])

    def test_invalid_or_shared_hostnames_do_not_change_azure(self):
        for host in ('https://agent.example.no', 'a..example.no', 'agent.example.no;echo', 'app.azurewebsites.net'):
            self.setUp()
            result = self.run_host('--apply', host)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(all(self.verb(call) in ('list', 'show') for call in self.az_calls()))
