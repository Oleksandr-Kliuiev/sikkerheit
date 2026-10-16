"""infra/scripts/setup.sh on the az stub: which database server main.bicep gets (RB-05) and that every refusal
stops the run before the first deployment."""
import json
import unittest

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


def rules(site="app-sikkerheit-prod-ab12c", connection=app_settings(), server_found=True, extra=()):
    return [*extra,
            rule(r"^account show --query tenantId", out="tenant-1"),
            rule(r"^account show --query name", out="Subscription"),
            rule(r"^ad signed-in-user show", out="me-1"),
            rule(r"^webapp list --resource-group " + GROUP, out=site),
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
        self.assertEqual(len(self.calls_matching("flexible-server show --resource-group " + GROUP + " --name " + HOST)), 1)

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


if __name__ == "__main__":
    unittest.main()
