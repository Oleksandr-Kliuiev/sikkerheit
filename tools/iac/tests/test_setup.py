"""infra/scripts/setup.sh on the az stub: which database server main.bicep gets (RB-05) and that every refusal
stops the run before the first deployment."""
import json
import unittest
from pathlib import Path

from script_harness import ScriptCase, rule

GROUP = "rg-sikkerheit-prod"
HOST = "psql-sikkerheit-prod-restored"
OUTPUTS = {name: {"value": value} for name, value in {
    "siteName": "app-sikkerheit-prod-ab12c", "productionHost": "app.example.net", "stagingHost": "staging.example.net",
    "productionPrincipalId": "p-prod", "stagingPrincipalId": "p-stage", "vaultName": "kv-sikkerheit-prod",
    "storageAccountName": "stsikkerheitprod", "databaseServerName": "psql-old", "databaseHost": "psql-old.example"}.items()}
ENV = {"SIKKERHEIT_ALERT_EMAIL": "drift@example.no"}


def app_settings(host=HOST):
    return f"Host={host}.postgres.database.azure.com;Database=sikkerheit;Username=x" if host else ""


def rules(site="app-sikkerheit-prod-ab12c", connection=app_settings(), server_found=True, extra=(), disk=rule(
        r"^postgres flexible-server show .*storageSizeGb", out="32")):
    return [*extra, disk,
            rule(r"^account show --query tenantId", out="tenant-1"),
            rule(r"^account show --query name", out="Subscription"),
            rule(r"^ad signed-in-user show", out="me-1"),
            rule(r"^webapp list --resource-group " + GROUP, out=site),
            rule(r"^webapp config appsettings list .*Hosting__AgentHosts", out="[]"),
            rule(r"^webapp config appsettings list", out=connection),
            rule(r"^postgres flexible-server show", rc=0 if server_found else 3, err="" if server_found else "not found"),
            rule(r"^deployment group create", out=json.dumps(OUTPUTS)),
            rule(r"^ad app list", out="app-id"),
            rule(r"^rest --method GET .*appRoles", out="role-id"),
            rule(r"^keyvault show", out="/vaults/kv"),
            rule(r"^keyvault certificate show --vault-name \S+ --name graph-reader --query", out="thumb"),
            rule(r"^storage container immutability-policy show .*--query state", out="Unlocked")]


class SetupTests(ScriptCase):
    def setup_run(self, *, env=None, **kwargs):
        return self.run_script("setup.sh", "prod", rules=rules(**kwargs), env={**ENV, **(env or {})})

    def deployments(self):
        return self.calls_matching("deployment group create")

    def assert_stopped_before_deployment(self, result):
        self.assertNotEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.deployments(), [], "the run deployed after a refusal\n" + self.describe(result))

    def storage(self):
        return [d for d in self.deployments() if "databaseStorageGb=" in d]

    def test_grown_disk_is_never_shrunk(self):
        result = self.setup_run(disk=rule(r"^postgres flexible-server show .*storageSizeGb", out="64"))
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(len(self.storage()), 2)
        for deployment in self.storage():
            self.assertIn("databaseStorageGb=64 ", deployment + " ")

    def test_first_install_gets_the_disk_of_the_template(self):
        result = self.setup_run(site="", connection="")
        self.assertEqual(result.returncode, 0, self.describe(result))
        for deployment in self.storage():
            self.assertIn("databaseStorageGb=32 ", deployment + " ")

    def test_unreadable_disk_size_stops_before_the_deployment(self):
        for disk in (rule(r"^postgres flexible-server show .*storageSizeGb", rc=1, err="throttled"),
                     rule(r"^postgres flexible-server show .*storageSizeGb", out="")):
            self.setUp()
            self.assert_stopped_before_deployment(self.setup_run(disk=disk))

    def test_first_install_lets_bicep_create_the_server(self):
        result = self.setup_run(site="", connection="")
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(len(self.deployments()), 2)
        for deployment in self.deployments():
            self.assertIn("databaseServerName= ", deployment + " ")
            self.assertNotIn("databaseServerName=psql", deployment)

    def test_repeated_install_keeps_the_server_of_the_connection_string(self):
        result = self.setup_run()
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(len(self.deployments()), 2)
        for deployment in self.deployments():
            self.assertIn("databaseServerName=" + HOST + " ", deployment + " ")
        self.assertEqual(len(self.calls_matching("flexible-server show --resource-group " + GROUP + " --name " + HOST)), 2)  # existence check and disk size

    def test_repeated_install_with_the_same_server_in_the_variable(self):
        result = self.setup_run(env={"SIKKERHEIT_DATABASE_SERVER": HOST})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertIn("databaseServerName=" + HOST, self.deployments()[0])

    def test_server_from_the_variable_when_the_connection_string_has_no_host(self):
        result = self.setup_run(connection="", env={"SIKKERHEIT_DATABASE_SERVER": HOST})
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertIn("databaseServerName=" + HOST, self.deployments()[0])

    def test_app_without_a_host_and_without_the_variable_stops(self):
        self.assert_stopped_before_deployment(self.setup_run(connection=""))

    def test_server_missing_from_the_group_stops(self):
        result = self.setup_run(server_found=False)
        self.assert_stopped_before_deployment(result)
        self.assertIn("No PostgreSQL server " + HOST, result.stderr)

    def test_variable_that_differs_from_the_connection_string_stops(self):
        result = self.setup_run(env={"SIKKERHEIT_DATABASE_SERVER": "psql-other"})
        self.assert_stopped_before_deployment(result)
        self.assertIn("psql-other", result.stderr)
        self.assertEqual(self.calls_matching("flexible-server show"), [])

    def test_az_failure_in_the_site_lookup_stops(self):
        extra = [rule(r"^webapp list --resource-group " + GROUP, rc=1, err="az: network down")]
        self.assert_stopped_before_deployment(self.setup_run(extra=extra))

    def test_az_failure_in_the_connection_string_lookup_stops(self):
        extra = [rule(r"^webapp config appsettings list", rc=1, err="az: throttled")]
        self.assert_stopped_before_deployment(self.setup_run(extra=extra))

    def test_the_alert_mailbox_is_required(self):
        result = self.run_script("setup.sh", "prod", rules=rules())
        self.assertEqual(result.returncode, 1, self.describe(result))
        self.assertEqual(self.az_calls(), [])

    def test_unknown_environment_is_refused(self):
        result = self.run_script("setup.sh", "staging", rules=rules(), env=ENV)
        self.assertEqual(result.returncode, 2, self.describe(result))
        self.assertEqual(self.az_calls(), [])

    def test_missing_hmac_keys_are_created_from_private_files_not_arguments(self):
        result = self.setup_run()
        self.assertEqual(result.returncode, 0, self.describe(result))
        for name in ('cursor-key', 'agents-nonce-key'):
            calls = self.calls_matching('keyvault secret set --vault-name kv-sikkerheit-prod --name ' + name)
            self.assertEqual(len(calls), 1)
            self.assertIn('--file ', calls[0])
            self.assertNotIn('--value ', calls[0])
            path = calls[0].split('--file ', 1)[1].split(' ', 1)[0]
            self.assertFalse(Path(path).exists(), 'secret file was not cleaned up')

    def test_existing_keys_are_never_rotated(self):
        result = self.setup_run(extra=[rule(r'^keyvault secret list ', out='/secrets/existing')])
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.calls_matching('keyvault secret set'), [])

    def test_key_vault_read_failure_does_not_replace_existing_keys(self):
        result = self.setup_run(extra=[rule(r'^keyvault secret list ', rc=1, err='throttled')])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls_matching('keyvault secret set'), [])
        self.assertEqual(len(self.deployments()), 1)

    def test_live_agent_hostname_and_minimum_version_are_preserved(self):
        live = json.dumps([{'name': 'Hosting__AgentHosts__0', 'value': 'agent.example.no'},
                           {'name': 'Agents__MinimumAgentVersion', 'value': '0.3.1'}])
        result = self.setup_run(extra=[rule(r'^webapp config appsettings list .*Hosting__AgentHosts', out=live)])
        self.assertEqual(result.returncode, 0, self.describe(result))
        for deployment in self.deployments():
            self.assertIn('agentHostname=agent.example.no ', deployment + ' ')
            self.assertIn('minimumAgentVersion=0.3.1 ', deployment + ' ')

    def test_live_job_concurrency_is_preserved(self):
        live = json.dumps([{'name': 'Jobs__CollectionConcurrency', 'value': '3'},
                           {'name': 'Jobs__MaintenanceConcurrency', 'value': '1'}])
        result = self.setup_run(extra=[rule(r'^webapp config appsettings list .*Hosting__AgentHosts', out=live)])
        self.assertEqual(result.returncode, 0, self.describe(result))
        for deployment in self.deployments():
            self.assertIn('collectionConcurrency=3 ', deployment + ' ')
            self.assertIn('maintenanceConcurrency=1 ', deployment + ' ')

    def test_explicit_job_concurrency_overrides_live_settings(self):
        live = json.dumps([{'name': 'Jobs__CollectionConcurrency', 'value': '3'},
                           {'name': 'Jobs__MaintenanceConcurrency', 'value': '2'}])
        result = self.setup_run(env={'SIKKERHEIT_COLLECTION_CONCURRENCY': '4', 'SIKKERHEIT_MAINTENANCE_CONCURRENCY': '1'},
                                extra=[rule(r'^webapp config appsettings list .*Hosting__AgentHosts', out=live)])
        self.assertEqual(result.returncode, 0, self.describe(result))
        for deployment in self.deployments():
            self.assertIn('collectionConcurrency=4 ', deployment + ' ')
            self.assertIn('maintenanceConcurrency=1 ', deployment + ' ')

    def test_invalid_job_concurrency_stops_before_deployment(self):
        for value in ('0', '9', '-1', 'unlimited'):
            with self.subTest(value=value):
                result = self.setup_run(env={'SIKKERHEIT_COLLECTION_CONCURRENCY': value})
                self.assertEqual(result.returncode, 2, self.describe(result))
                self.assertEqual(self.deployments(), [])


if __name__ == "__main__":
    unittest.main()
