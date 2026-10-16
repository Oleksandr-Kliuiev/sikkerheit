"""The static check of the MSI must fail on every rule it states: each case breaks Package.wxs once."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_installer as c  # noqa: E402

WXS, SCRIPT = c.WXS.read_text(encoding="utf-8"), c.SCRIPT.read_text(encoding="utf-8")
PROGRAM, ENV = c.PROGRAM.read_text(encoding="utf-8"), c.ENVIRONMENT.read_text(encoding="utf-8")

BREAKS = {
    "arm64 allowed": ('NATIVEARCH = &quot;AMD64&quot;', 'NATIVEARCH'),
    "server allowed": ("MsiNTProductType = 1", "MsiNTProductType = 3"),
    "old build allowed": ("WindowsBuild &gt;= 17763", "WindowsBuild &gt;= 7601"),
    "no restart": ('FirstFailureActionType="restart"', 'FirstFailureActionType="none"'),
    "only crashes restart": ('FailureActionsWhen="failedToStopOrReturnedError"', 'FailureActionsWhen="failedToStop"'),
    "restart delay": ('RestartServiceDelayInSeconds="60"', 'RestartServiceDelayInSeconds="5"'),
    "not LocalSystem": ('Account="LocalSystem"', 'Account="NT AUTHORITY\\LocalService"'),
    "upgrade removes data": ('Schedule="afterInstallExecute"', 'Schedule="afterInstallValidate"'),
    "no rollback": ('AllowDowngrades="yes"', 'AllowDowngrades="no"'),
    "proxy visible in log": ('Value="PROXY"', 'Value="OTHER"'),
    "data open to users": ('<util:PermissionEx User="SYSTEM" GenericAll="yes" />',
                           '<util:PermissionEx User="SYSTEM" GenericAll="yes" /><util:PermissionEx User="Users" GenericRead="yes" />'),
    "data kept on uninstall": ('<util:RemoveFolderEx On="uninstall" Property="DATADIR" />', ''),
    "fixed server": ("Agent__ServerUrl=$(ServerUrl)[~]", "Agent__ServerUrl=https://x.example[~]"),
    "key in registry": ("Agent__Proxy=[PROXY]", "Agent__Proxy=[PROXY][~]Agent__EnrollmentKey=x"),
    "credentials in proxy allowed": ('NOT PROXY OR NOT (PROXY &gt;&lt; &quot;@&quot;)', 'NOT PROXY'),
}


class InstallerCheck(unittest.TestCase):
    def test_current_file_is_clean(self):
        self.assertEqual([], c.check(WXS, SCRIPT, PROGRAM, ENV))

    def test_each_rule_fails_when_broken(self):
        for title, (old, new) in BREAKS.items():
            with self.subTest(title):
                self.assertIn(old, WXS)
                self.assertTrue(c.check(WXS.replace(old, new, 1), SCRIPT, PROGRAM, ENV), title)

    def test_name_shared_with_the_script(self):
        self.assertTrue(c.check(WXS, SCRIPT.replace("'Sikkerheit Agent'", "'Other'"), PROGRAM, ENV))

    def test_malformed_xml(self):
        self.assertTrue(c.check("<Wix>", SCRIPT, PROGRAM, ENV))


if __name__ == "__main__":
    unittest.main()
