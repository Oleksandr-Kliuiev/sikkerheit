"""Offline harness for the tests of infra/scripts: the script runs in a copy of the tree with the stubs of
tools/iac/tests/stubs first in PATH, so no test reaches Azure, npm or the network."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

PRODUCTION = "rg-sikkerheit-prod"
DRILL = "rg-sikkerheit-drill"


def rule(match, out=None, rc=0, outs=None, err=None, file=None, file_arg=None):
    """One answer of the az stub: the regex is matched against the arguments of the call."""
    result = {"match": match, "rc": rc}
    for key, value in (("out", out), ("outs", outs), ("err", err), ("file", file), ("fileArg", file_arg)):
        if value is not None:
            result[key] = value
    return result


class ScriptCase(unittest.TestCase):
    """A fresh tree per test: infra/scripts copied, infra/.state empty, an empty az journal."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sikkerheit-scripts-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "tree"
        scripts = self.root / "infra" / "scripts"
        scripts.mkdir(parents=True)
        for script in (REPO / "infra" / "scripts").glob("*.sh"):
            shutil.copy(script, scripts / script.name)
        for tree in ("infra/bicep/modules", "src/Portal", "src/Sikkerheit.Host"):
            (self.root / tree).mkdir(parents=True)
        self.bin = self.tmp / "bin"
        shutil.copytree(HERE / "stubs", self.bin)
        self.log = self.tmp / "az.log"
        self.log.write_text("")
        self.rules_file = self.tmp / "rules.json"
        self.rules = []

    def run_script(self, name, *args, rules=(), env=None):
        """Runs infra/scripts/<name> with the rules; the first matching rule wins, so specific rules go first."""
        self.rules_file.write_text(json.dumps(list(rules)))
        for counter in self.tmp.glob("rules.json.count.*"):
            counter.unlink()
        environment = {key: value for key, value in os.environ.items() if not key.startswith("SIKKERHEIT_")}
        environment.update({"PATH": f"{self.bin}:{environment['PATH']}", "AZ_LOG": str(self.log),
                            "AZ_RULES": str(self.rules_file), "TMPDIR": str(self.tmp)})
        environment.update(env or {})
        return subprocess.run(["bash", str(self.root / "infra" / "scripts" / name), *args], env=environment,
                              capture_output=True, text=True, errors="replace", timeout=120, check=False)

    def az_calls(self):
        """The journal of az: one line per call, the arguments after «az»."""
        return [line for line in self.log.read_text().splitlines() if not line.startswith(("npm ", "dotnet "))]

    def calls_matching(self, text):
        return [line for line in self.az_calls() if text in line]

    @staticmethod
    def verb(call):
        """«group delete --name x» → delete: the last word before the first option."""
        words = []
        for word in call.split():
            if word.startswith("-"):
                break
            words.append(word)
        return words[-1]

    def state_file(self, name):
        return self.root / "infra" / ".state" / name

    def describe(self, result):
        return f"exit {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\njournal:\n" + \
            "\n".join(self.az_calls())
