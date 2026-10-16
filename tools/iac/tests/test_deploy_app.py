"""infra/scripts/deploy-app.sh test on the az stub: B1 has no slots, so the migrations access is attached for the
deployment and removed again; the database host is the one of the connection string of the app."""
import json
import unittest

from script_harness import ScriptCase, rule

GROUP = "rg-sikkerheit-test"
SITE = "app-sikkerheit-test-ab12c"
LIVE_HOST = "psql-sikkerheit-test-restored"
STALE_HOST = "psql-sikkerheit-test-old"
MIGRATIONS = "/ids/id-sikkerheit-test-migrations"


def rules(extra=()):
    return [*extra,
            rule(r"^webapp list --resource-group " + GROUP, out=SITE),
            rule(r"^webapp show .*defaultHostName", out="app.example.net"),
            rule(r"^webapp identity assign", out=""),
            rule(r"^webapp identity show .*principalId", out="p-app"),
            rule(r"^webapp identity show", out=json.dumps({"userAssignedIdentities": {MIGRATIONS.upper(): {}}})),
            rule(r"^identity show", out=json.dumps({"id": MIGRATIONS, "name": "id-sikkerheit-test-migrations", "clientId": "c-m"})),
            rule(r"^webapp config appsettings list",
                 out=f"Host={LIVE_HOST}.postgres.database.azure.com;Database=sikkerheit;Username=app")]


class DeployAppTests(ScriptCase):
    def write_state(self):
        outputs = {"siteName": SITE, "productionHost": "app.example.net", "productionPrincipalId": "p-state",
                   "databaseServerName": STALE_HOST, "databaseHost": STALE_HOST + ".postgres.database.azure.com"}
        path = self.state_file("test.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({key: {"value": value} for key, value in outputs.items()}))

    def deploy(self, *, state=True, extra=()):
        if state:
            self.write_state()
        return self.run_script("deploy-app.sh", "test", rules=rules(extra))

    def settings_calls(self):
        return self.calls_matching("webapp config appsettings set")

    def test_owner_connection_string_uses_the_host_of_the_app_not_of_the_state(self):
        result = self.deploy()
        self.assertEqual(result.returncode, 0, self.describe(result))
        attach = self.settings_calls()[0]
        self.assertIn(f"ConnectionStrings__SikkerheitOwner=Host={LIVE_HOST}.postgres.database.azure.com;", attach)
        self.assertNotIn(STALE_HOST, "\n".join(self.az_calls()))

    def test_same_host_without_the_state_file(self):
        result = self.deploy(state=False, extra=[rule(r"^webapp list", out=SITE)])
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertIn(f"Host={LIVE_HOST}.", self.settings_calls()[0])

    def test_migrations_access_is_attached_then_removed(self):
        result = self.deploy()
        self.assertEqual(result.returncode, 0, self.describe(result))
        calls = self.az_calls()
        assign = next(i for i, c in enumerate(calls) if c.startswith("webapp identity assign"))
        deploy = next(i for i, c in enumerate(calls) if c.startswith("webapp deploy"))
        remove = next(i for i, c in enumerate(calls) if c.startswith("webapp identity remove"))
        restart = max(i for i, c in enumerate(calls) if c.startswith("webapp restart"))
        self.assertLess(assign, deploy)
        self.assertLess(deploy, remove)
        self.assertLess(remove, restart)
        self.assertIn("Database__MigrateOnStart=false", self.settings_calls()[-1])
        self.assertIn("Database__MigrateOnStart=true", self.settings_calls()[0])

    def test_failed_deployment_still_removes_the_migrations_access(self):
        result = self.deploy(extra=[rule(r"^webapp deploy", rc=1, err="deploy failed")])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls_matching("webapp identity remove")), 1, self.describe(result))
        self.assertIn("Database__MigrateOnStart=false", self.settings_calls()[-1])

    def test_no_database_host_in_the_connection_string_stops_before_any_change(self):
        result = self.deploy(extra=[rule(r"^webapp config appsettings list", out="")])
        self.assertNotEqual(result.returncode, 0, self.describe(result))
        self.assertEqual(self.calls_matching("webapp deploy"), [])
        self.assertEqual(self.calls_matching("webapp identity assign"), [])

    def test_production_without_a_staging_slot_is_refused(self):
        result = self.run_script("deploy-app.sh", "prod", rules=[rule(r"^webapp list", out="app-sikkerheit-prod-x"),
                                                                 rule(r"^webapp show .*--slot", out="")])
        self.assertEqual(result.returncode, 1, self.describe(result))
        self.assertEqual(self.calls_matching("webapp deploy"), [])


if __name__ == "__main__":
    unittest.main()
