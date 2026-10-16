"""Static check of the MSI description (src/Agent/Installer/Package.wxs) against the pieces of the repository it must agree with.

WiX cannot be built without Windows here, so what a build would only run is checked as text: the conditions of installation,
the recovery actions, the properties, the data directory, and the names shared with the agent and the RMM script (06 «Распространение
агента через RMM»). Run: python3 -I tools/rmm/check_installer.py. Exit code 1 and "[installer] ..." lines on any violation.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WXS = ROOT / "src/Agent/Installer/Package.wxs"
SCRIPT = ROOT / "tools/rmm/Sikkerheit-Rmm.ps1"
PROGRAM = ROOT / "src/Agent/Sikkerheit.Agent/Program.cs"
ENVIRONMENT = ROOT / "src/Agent/Sikkerheit.Agent/Runtime/AgentEnvironment.cs"

NS = {"w": "http://wixtoolset.org/schemas/v4/wxs", "util": "http://wixtoolset.org/schemas/v4/wxs/util"}


def _find(root: ET.Element, path: str) -> list[ET.Element]:
    return root.findall(path, NS)


def check(wxs_text: str, script_text: str, program_text: str, environment_text: str) -> list[str]:
    problems: list[str] = []
    try:
        root = ET.fromstring(wxs_text)
    except ET.ParseError as error:
        return [f"[installer] Package.wxs is not well-formed XML: {error}"]
    package = root.find("w:Package", NS)
    if package is None:
        return ["[installer] no Package element"]

    # names shared with the RMM script and the agent
    product = re.search(r"\$script:ProductName\s*=\s*'([^']+)'", script_text)
    if not product or product.group(1) != package.get("Name"):
        problems.append("[installer] Package Name differs from $script:ProductName of the RMM script (the uninstall search uses it)")
    service_name = re.search(r'ServiceName\s*=\s*"([^"]+)"', program_text)
    install = package.find(".//w:ServiceInstall", NS)
    if install is None:
        problems.append("[installer] no ServiceInstall")
    else:
        if not service_name or install.get("Name") != service_name.group(1):
            problems.append("[installer] ServiceInstall Name differs from AgentHost.ServiceName")
        if install.get("Account") != "LocalSystem":
            problems.append("[installer] the service must run as LocalSystem")
        if install.get("Start") != "auto":
            problems.append("[installer] the service must start automatically")
        config = install.find("util:ServiceConfig", NS)
        if config is None:
            problems.append("[installer] no recovery actions (util:ServiceConfig)")
        else:
            for attribute in ("FirstFailureActionType", "SecondFailureActionType", "ThirdFailureActionType"):
                if config.get(attribute) != "restart":
                    problems.append(f"[installer] recovery action {attribute} must be restart")
            if config.get("FailureActionsWhen") != "failedToStopOrReturnedError":
                problems.append("[installer] recovery actions must also apply when the service stops with an error code")
            if config.get("RestartServiceDelayInSeconds") != "60":
                problems.append("[installer] the restart must be 1 minute after a failure")
    control = package.find(".//w:ServiceControl", NS)
    if control is None or control.get("Stop") != "both" or control.get("Remove") != "uninstall" or control.get("Start") != "install":
        problems.append("[installer] ServiceControl must start on install, stop on install and uninstall and remove the service")

    # upgrade and rollback keep the data directory
    upgrade = package.find("w:MajorUpgrade", NS)
    if upgrade is None or upgrade.get("AllowDowngrades") != "yes":
        problems.append("[installer] MajorUpgrade must allow downgrades (rollback to an approved version)")
    elif upgrade.get("Schedule") != "afterInstallExecute":
        problems.append("[installer] MajorUpgrade must be scheduled afterInstallExecute so that an upgrade does not remove the data directory")

    # conditions of installation
    conditions = [c.get("Condition", "") for c in _find(package, "w:Launch")]
    required = {
        "client OS": "MsiNTProductType = 1",
        "64-bit OS": "VersionNT64",
        "native x64": 'NATIVEARCH = "AMD64"',
        "build 17763": "WindowsBuild >= 17763",
        "proxy without credentials": 'NOT (PROXY >< "@")',
    }
    for title, fragment in required.items():
        if not any(fragment in c for c in conditions):
            problems.append(f"[installer] no launch condition: {title} ({fragment})")
    build = re.search(r"\$script:MinimumBuild\s*=\s*(\d+)", script_text)
    if not build or build.group(1) != "17763":
        problems.append("[installer] the minimum build of the RMM script is not 17763")
    arch = package.find(".//w:RegistrySearch[@Id='NativeArchitecture']", NS)
    if arch is None or arch.get("Name") != "PROCESSOR_ARCHITECTURE" or arch.get("Bitness") != "always64":
        problems.append("[installer] the native architecture must be read from PROCESSOR_ARCHITECTURE of the 64-bit registry view")

    # properties
    proxy = package.find("w:Property[@Id='PROXY']", NS)
    if proxy is None or proxy.get("Secure") != "yes":
        problems.append("[installer] the public property PROXY must be declared with Secure=yes")
    hidden = package.find("w:Property[@Id='MsiHiddenProperties']", NS)
    if hidden is None or "PROXY" not in (hidden.get("Value") or "").split(";"):
        problems.append("[installer] MsiHiddenProperties must hide PROXY from the installer log")
    if not re.search(r"public string\? Proxy", environment_text) or 'Section = "Agent"' not in environment_text:
        problems.append("[installer] AgentOptions has no Proxy in section Agent")
    values = [v.get("Value", "") for v in _find(package, ".//w:RegistryValue")]
    if not any("Agent__ServerUrl=$(ServerUrl)" in v for v in values) or not any("Agent__Proxy=[PROXY]" in v for v in values):
        problems.append("[installer] the service environment must set Agent__ServerUrl and (with PROXY) Agent__Proxy")
    for value in values:
        if re.search(r"(?i)sikk_|enroll|secret|password|key", value):
            problems.append("[installer] a registry value of the service mentions a key or a secret")
    if "http" in re.sub(r"\$\(ServerUrl\)", "", " ".join(values)).lower():
        problems.append("[installer] the server URL must come from the build variable ServerUrl, not from a literal")
    components = {c.get("Id"): c.get("Condition") for c in _find(package, ".//w:Component")}
    if components.get("ServiceEnvironment") != "NOT PROXY" or components.get("ServiceEnvironmentWithProxy") != "PROXY":
        problems.append("[installer] the two environment components must be conditioned on NOT PROXY and PROXY")

    # data directory
    default_dir = re.search(r'CommonApplicationData\), "Sikkerheit", "Agent"', environment_text)
    data = package.find(".//w:Directory[@Id='DATADIR']", NS)
    parent = package.find(".//w:Directory[@Id='DATAPARENT']", NS)
    if not default_dir or data is None or parent is None or data.get("Name") != "Agent" or parent.get("Name") != "Sikkerheit":
        problems.append(r"[installer] the data directory must be %ProgramData%\Sikkerheit\Agent as in AgentOptions")
    permissions = _find(package, ".//util:PermissionEx")
    if len(permissions) != 1 or permissions[0].get("User") != "SYSTEM" or permissions[0].get("GenericAll") != "yes":
        problems.append("[installer] the data directory must have exactly one permission: SYSTEM full control")
    remove = package.find(".//util:RemoveFolderEx", NS)
    if remove is None or remove.get("On") != "uninstall" or remove.get("Property") != "DATADIR":
        problems.append("[installer] uninstall must remove the data directory (RemoveFolderEx On=uninstall)")
    folder = package.find(".//w:Component[@Id='DataDirectory']", NS)
    if folder is None or not folder.get("Guid"):
        problems.append("[installer] the data directory component needs a fixed Guid (the same in every version)")

    # one entry per component guid, a fixed upgrade code, no secrets or fixed server in the file
    guids = [c.get("Guid") for c in _find(package, ".//w:Component") if c.get("Guid")]
    if len(guids) != len(set(guids)) or not package.get("UpgradeCode"):
        problems.append("[installer] component guids must be unique and UpgradeCode fixed")
    if re.search(r"sikk_[A-Za-z0-9_-]{10,}", wxs_text):
        problems.append("[installer] a registration key is in Package.wxs")
    return problems


def main() -> int:
    problems = check(WXS.read_text(encoding="utf-8"), SCRIPT.read_text(encoding="utf-8"),
                     PROGRAM.read_text(encoding="utf-8"), ENVIRONMENT.read_text(encoding="utf-8"))
    for problem in problems:
        print(problem)
    if not problems:
        print("installer: Package.wxs agrees with the agent and the RMM script")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
