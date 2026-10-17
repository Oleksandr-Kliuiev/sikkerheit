"""Run the real Production bootstrap with synthetic credentials, without starting jobs, HTTP or Azure clients."""
import argparse
import base64
import os
import pathlib
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assembly', type=pathlib.Path, required=True)
    parser.add_argument('--negative-tests', action='store_true', help='Also reject unsafe job concurrency settings')
    args = parser.parse_args()
    key = base64.b64encode(bytes(range(32))).decode()
    settings = {
        'ConnectionStrings__Sikkerheit': 'Host=database.invalid;Database=sikkerheit;Username=app;Ssl Mode=VerifyFull',
        'Auth__Entra__TenantId': '11111111-1111-4111-8111-111111111111',
        'Auth__Entra__ClientId': '22222222-2222-4222-8222-222222222222',
        'Auth__Entra__RedirectUri': 'https://portal.invalid/auth/callback',
        'M365__ClientId': '33333333-3333-4333-8333-333333333333',
        'M365__CompanyTenantId': '11111111-1111-4111-8111-111111111111',
        'M365__KeyVaultUri': 'https://vault.invalid/', 'M365__CertificateName': 'graph-reader',
        'M365__ConsentRedirectUri': 'https://portal.invalid/consent-complete',
        'DataProtection__BlobUri': 'https://storage.invalid/dataprotection/keys.xml',
        'DataProtection__KeyVaultKeyId': 'https://vault.invalid/keys/dataprotection',
        'SecurityLog__ContainerUri': 'https://storage.invalid/security-log',
        'Storage__BlobServiceUri': 'https://storage.invalid/',
        'Cursors__Key': key, 'Agents__NonceKey': key,
        'Hosting__PortalHosts__0': 'portal.invalid', 'Hosting__AgentHosts__0': 'disabled.invalid',
        'ASPNETCORE_ENVIRONMENT': 'Production', 'DOTNET_EnableDiagnostics': '0',
        'Jobs__Enabled': 'false',
        'Jobs__CollectionConcurrency': '8', 'Jobs__MaintenanceConcurrency': '2',
    }
    environment = {key: value for key, value in os.environ.items() if key in ('PATH', 'HOME', 'DOTNET_ROOT', 'TMPDIR')}
    for profile in ('M365', 'Windows', 'staging'):
        values = dict(settings)
        if profile != 'M365':
            values['Hosting__AgentHosts__0'] = 'agent.invalid' if profile == 'Windows' else 'portal.invalid'
        if profile == 'staging':
            values['WEBSITE_SLOT_NAME'] = 'staging'
        result = subprocess.run(['dotnet', str(args.assembly.resolve()), 'check-configuration'],
                                env={**environment, **values}, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode:
            print(f'FAIL {profile} Production bootstrap:\n{result.stdout}{result.stderr}')
            return 1
        print(f'PASS {profile} Production bootstrap (synthetic configuration; no external access)')
    if args.negative_tests:
        for key, value in (('Jobs__CollectionConcurrency', '0'), ('Jobs__CollectionConcurrency', '9'),
                           ('Jobs__MaintenanceConcurrency', '0'), ('Jobs__MaintenanceConcurrency', '9')):
            result = subprocess.run(['dotnet', str(args.assembly.resolve()), 'check-configuration'],
                                    env={**environment, **settings, key: value}, capture_output=True, text=True,
                                    timeout=30, check=False)
            if result.returncode == 0 or 'Jobs:CollectionConcurrency' not in result.stderr:
                print(f'FAIL unsafe {key}={value} was not rejected by job options validation')
                return 1
            print(f'PASS rejected unsafe {key}={value}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
