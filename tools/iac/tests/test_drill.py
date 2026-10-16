"""infra/scripts/drill.sh on the az stub (RB-05, «Учебное восстановление»): production is only read, the drill group is
the only thing created or deleted."""
import datetime
import json
import unittest
import zipfile

from script_harness import DRILL, PRODUCTION, ScriptCase, rule

SITE = "app-sikkerheit-prod-ab12c"
SERVER = "psql-sikkerheit-prod-restored"
READ_VERBS = ("show", "list", "exists")


def utc(delta):
    return (datetime.datetime.now(datetime.timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def app_settings():
    return json.dumps([
        {"name": "ConnectionStrings__Sikkerheit", "value": f"Host={SERVER}.postgres.database.azure.com;Database=sikkerheit;"},
        {"name": "Storage__BlobServiceUri", "value": "https://stsikkerheitprod.blob.core.windows.net"},
        {"name": "SecurityLog__ContainerUri", "value": "https://stsikkerheitprod.blob.core.windows.net/security-log"}])


def production_rules(earliest=None, group_exists="false"):
    earliest = earliest or utc(datetime.timedelta(days=-7))
    return [
        rule(r"^group exists", out=group_exists),
        rule(r"^webapp list --resource-group " + PRODUCTION, out=SITE),
        rule(r"^webapp config appsettings list --resource-group " + PRODUCTION, out=app_settings()),
        rule(r"^postgres flexible-server show --resource-group " + PRODUCTION + " --name " + SERVER,
             out=json.dumps({"id": "/subscriptions/s/servers/" + SERVER, "name": SERVER,
                             "location": "norwayeast", "earliest": earliest})),
        rule(r"^identity show .*-migrations", out=json.dumps({"id": "/ids/migrations", "clientId": "c-m", "principalId": "p-m"})),
        rule(r"^identity show .*-restore", out=json.dumps({"id": "/ids/restore", "clientId": "c-r"})),
        rule(r"^webapp identity assign", out="principal-of-drill-site"),
        rule(r"^postgres flexible-server show --resource-group " + DRILL,
             out=json.dumps({"state": "Ready", "fqdn": "psql-drill.postgres.database.azure.com", "access": "Disabled",
                             "entra": "Enabled", "password": "Disabled"})),
        rule(r"^postgres flexible-server microsoft-entra-admin list", out="p-m"),
    ]


class DrillTests(ScriptCase):
    def start(self, since=None, rules=None):
        since = since or utc(datetime.timedelta(hours=-1))
        package = self.tmp / "app.zip"
        package.write_bytes(b"PK")
        result = self.run_script("drill.sh", "start", "--since", since, "--package", str(package),
                                 rules=rules if rules is not None else production_rules())
        return result, since

    def started(self):
        result, since = self.start()
        self.assertEqual(result.returncode, 0, self.describe(result))
        return since, json.loads(self.state_file("drill.json").read_text())

    def test_start_only_reads_production_and_assigns_no_roles(self):
        result, _ = self.start()
        self.assertEqual(result.returncode, 0, self.describe(result))
        calls = self.az_calls()
        self.assertTrue(any(c.startswith("group create --name " + DRILL) and "environment=drill" in c for c in calls))
        self.assertTrue(any(c.startswith("postgres flexible-server restore --resource-group " + DRILL) for c in calls))
        self.assertTrue(any(c.startswith("webapp deploy --resource-group " + DRILL) for c in calls))
        production = [c for c in calls if PRODUCTION in c]
        self.assertTrue(production)
        for call in production:
            self.assertIn(self.verb(call), READ_VERBS, "production is changed: " + call)
        self.assertEqual(self.calls_matching("role assignment"), [], "drill.sh assigns roles")
        restore = self.calls_matching("flexible-server restore")[0]
        self.assertIn("--source-server /subscriptions/s/servers/" + SERVER, restore)
        self.assertIn("--restore-time", restore)

    def test_start_refuses_with_a_previous_drill(self):
        result, _ = self.start(rules=production_rules(group_exists="true"))
        self.assertEqual(result.returncode, 1, self.describe(result))
        self.assertEqual(self.calls_matching("group create"), [])

    def test_start_refuses_a_time_before_the_earliest_restore_point(self):
        result, _ = self.start(rules=production_rules(earliest=utc(datetime.timedelta(minutes=-30))))
        self.assertEqual(result.returncode, 2, self.describe(result))
        self.assertEqual(self.calls_matching("group create"), [])

    def test_start_refuses_a_time_in_the_future_or_a_malformed_one(self):
        for since in (utc(datetime.timedelta(hours=2)), "yesterday"):
            result, _ = self.start(since=since)
            self.assertEqual(result.returncode, 2, self.describe(result))
        self.assertEqual(self.calls_matching("group create"), [])

    def test_start_without_the_restore_identity_changes_nothing(self):
        result, _ = self.start(rules=[rule(r"^identity show .*-restore", rc=3, err="not found")] + production_rules())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls_matching("group create"), [])

    def test_failed_start_points_to_cleanup(self):
        result, _ = self.start(rules=[rule(r"^postgres flexible-server restore", rc=1, err="boom")] + production_rules())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("drill.sh cleanup", result.stdout)

    def check(self, report_name, restored, **changes):
        report = {"drill": True, "since": restored, "verification": {"passed": True, "problems": []},
                  "recordsRead": 3, "records": [{"outcome": "applied"}], "deletionsPostponed": 0, "policyEpochs": 1,
                  "orphanFiles": [{"container": "files", "key": "k", "moved": False}], "leasesReset": 0, "steps": []}
        report.update(changes)
        archive = self.tmp / "logs.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("LogFiles/" + report_name, json.dumps(report))
        return self.run_script("drill.sh", "check", rules=[
            rule(r"^webapp log download", file=str(archive), file_arg="--log-file")])

    def test_check_passes_on_a_drill_report(self):
        since, state = self.started()
        result = self.check(state["report"], since)
        self.assertEqual(result.returncode, 0, self.describe(result))
        self.assertIn("Drill passed", result.stdout)

    def test_check_fails_on_a_report_that_moved_files_or_is_not_a_drill(self):
        since, state = self.started()
        moved = self.check(state["report"], since, orphanFiles=[{"container": "files", "key": "k", "moved": True}])
        self.assertEqual(moved.returncode, 1, self.describe(moved))
        self.assertIn("DRILL FAILED", moved.stdout)
        for changes in ({"drill": False}, {"verification": {"passed": False, "problems": ["x"]}}, {"since": "2000-01-01T00:00:00Z"}):
            result = self.check(state["report"], since, **changes)
            self.assertEqual(result.returncode, 1, self.describe(result))

    def test_check_without_start_stops(self):
        result = self.run_script("drill.sh", "check")
        self.assertEqual(result.returncode, 1, self.describe(result))

    def test_cleanup_deletes_only_the_group_tagged_drill(self):
        self.started()
        self.log.write_text("")
        done = self.run_script("drill.sh", "cleanup", rules=[
            rule(r"^group exists", outs=["true", "false"]), rule(r"^group show", out="drill")])
        self.assertEqual(done.returncode, 0, self.describe(done))
        self.assertEqual(self.calls_matching("group delete"), ["group delete --name " + DRILL + " --yes"])
        self.assertFalse(self.state_file("drill.json").exists())

    def test_cleanup_refuses_a_group_without_the_drill_tag(self):
        done = self.run_script("drill.sh", "cleanup", rules=[
            rule(r"^group exists", out="true"), rule(r"^group show", out="prod")])
        self.assertEqual(done.returncode, 1, self.describe(done))
        self.assertEqual(self.calls_matching("group delete"), [])

    def test_cleanup_without_a_group_deletes_nothing(self):
        done = self.run_script("drill.sh", "cleanup", rules=[rule(r"^group exists", out="false")])
        self.assertEqual(done.returncode, 0, self.describe(done))
        self.assertEqual(self.calls_matching("group delete"), [])


if __name__ == "__main__":
    unittest.main()
