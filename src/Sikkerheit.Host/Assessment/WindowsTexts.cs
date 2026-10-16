namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Texts of the Windows and server rules in nb, nn and en (01 «Язык портала и отчёта»): title and recommendation per check,
/// explanation per outcome key. Drafts for review by the person who approves the texts (question 9 in 08).
/// </summary>
internal static class WindowsTexts
{
    public static readonly Dictionary<string, (string Nb, string Nn, string En)> Titles = new(StringComparer.Ordinal)
    {
        ["WIN-001"] = ("Lite ledig plass på systemdisken", "Lite ledig plass på systemdisken", "Low free space on the system volume"),
        ["WIN-002"] = ("BitLocker beskytter ikke systemdisken", "BitLocker vernar ikkje systemdisken", "BitLocker does not protect the system volume"),
        ["WIN-003"] = ("Ingen aktivt godkjent antivirusprogram", "Inga aktivt godkjend antivirusprogram", "No active approved antivirus"),
        ["WIN-004"] = ("Utdaterte signaturer i Microsoft Defender", "Utdaterte signaturar i Microsoft Defender", "Outdated Microsoft Defender signatures"),
        ["WIN-005"] = ("Brannmur er ikke aktiv", "Brannmur er ikkje aktiv", "Firewall is not active"),
        ["WIN-006"] = ("Windows Update søker ikke etter oppdateringer", "Windows Update søkjer ikkje etter oppdateringar", "Windows Update is not searching for updates"),
        ["WIN-007"] = ("Maskinen venter på omstart", "Maskina ventar på omstart", "The computer is waiting for a restart"),
        ["WIN-008"] = ("Uventede lokale administratorer", "Uventa lokale administratorar", "Unexpected local administrators"),
        ["WIN-009"] = ("Secure Boot er ikke slått på", "Secure Boot er ikkje slått på", "Secure Boot is not turned on"),
        ["WIN-010"] = ("Maskinen er ikke koblet til riktig tenant", "Maskina er ikkje kopla til rett tenant", "The computer is not joined to the expected tenant"),
        ["WIN-011"] = ("Operativsystem", "Operativsystem", "Operating system"),
        ["SYS-001"] = ("Ferske data fra agenten", "Ferske data frå agenten", "Fresh data from the agent"),
        ["SYS-002"] = ("Windows-versjonen får ikke lenger oppdateringer", "Windows-versjonen får ikkje lenger oppdateringar", "The Windows version is out of servicing"),
        ["SYS-003"] = ("Windows mangler sikkerhetsoppdateringer", "Windows manglar tryggingsoppdateringar", "Windows is missing security updates"),
    };

    public static readonly Dictionary<string, (string Nb, string Nn, string En)> Recommendations = new(StringComparer.Ordinal)
    {
        ["WIN-001"] = ("Frigjør plass på systemdisken eller bytt til en større disk.", "Frigjer plass på systemdisken eller byt til ein større disk.", "Free up space on the system volume or move to a larger disk."),
        ["WIN-002"] = ("Slå på BitLocker for systemdisken og lagre gjenopprettingsnøkkelen i Entra ID.", "Slå på BitLocker for systemdisken og lagre gjenopprettingsnøkkelen i Entra ID.", "Turn on BitLocker for the system volume and store the recovery key in Entra ID."),
        ["WIN-003"] = ("Installer eller aktiver et godkjent antivirusprogram.", "Installer eller aktiver eit godkjent antivirusprogram.", "Install or activate an approved antivirus."),
        ["WIN-004"] = ("Kontroller at Microsoft Defender får oppdatert signaturer, og kjør oppdatering.", "Kontroller at Microsoft Defender får oppdaterte signaturar, og køyr oppdatering.", "Check that Microsoft Defender can update its signatures and run an update."),
        ["WIN-005"] = ("Slå på Windows-brannmuren for alle påkrevde profiler, eller bruk en godkjent brannmur.", "Slå på Windows-brannmuren for alle påkravde profilar, eller bruk ein godkjend brannmur.", "Turn on Windows Firewall for all required profiles, or use an approved firewall."),
        ["WIN-006"] = ("Kontroller Windows Update-tjenesten og WSUS- eller RMM-policyen.", "Kontroller Windows Update-tenesta og WSUS- eller RMM-policyen.", "Check the Windows Update service and the WSUS or RMM policy."),
        ["WIN-007"] = ("Start maskinen på nytt ved første anledning.", "Start maskina på nytt ved første høve.", "Restart the computer at the first opportunity."),
        ["WIN-008"] = ("Fjern kontoene som ikke skal være lokale administratorer, eller legg dem til i policyen.", "Fjern kontoane som ikkje skal vere lokale administratorar, eller legg dei til i policyen.", "Remove the accounts that should not be local administrators, or add them to the policy."),
        ["WIN-009"] = ("Slå på Secure Boot i UEFI-oppsettet; maskiner med eldre BIOS må vurderes for utskifting.", "Slå på Secure Boot i UEFI-oppsettet; maskiner med eldre BIOS må vurderast for utskifting.", "Turn on Secure Boot in the UEFI setup; computers with legacy BIOS should be considered for replacement."),
        ["WIN-010"] = ("Koble maskinen til kundens Entra-tenant.", "Kopl maskina til Entra-tenanten til kunden.", "Join the computer to the customer's Entra tenant."),
        ["WIN-011"] = ("Ingen tiltak.", "Ingen tiltak.", "No action."),
        ["SYS-001"] = ("Ingen tiltak.", "Ingen tiltak.", "No action."),
        ["SYS-002"] = ("Oppgrader maskinen til en Windows-versjon som får oppdateringer. For Windows 10 22H2 kan betalt ESU være et alternativ.", "Oppgrader maskina til ein Windows-versjon som får oppdateringar. For Windows 10 22H2 kan betalt ESU vere eit alternativ.", "Upgrade the computer to a Windows version that is serviced. For Windows 10 22H2, paid ESU can be an alternative."),
        ["SYS-003"] = ("Installer siste kumulative sikkerhetsoppdatering og start maskinen på nytt.", "Installer siste kumulative tryggingsoppdatering og start maskina på nytt.", "Install the latest cumulative security update and restart the computer."),
    };

    private static (string, string, string) T(string nb, string nn, string en) => (nb, nn, en);

    public static readonly Dictionary<string, (string Nb, string Nn, string En)> Explanations = new(StringComparer.Ordinal)
    {
        ["win.clock_inconsistent"] = T("Klokken på maskinen avviker fra serveren; resultatet kan ikke fastslås.", "Klokka på maskina avvik frå tenaren; resultatet kan ikkje fastslåast.", "The clock of the computer differs from the server; the result cannot be determined."),
        ["win.unavailable.permission_denied"] = T("Agenten fikk ikke tilgang til dataene.", "Agenten fekk ikkje tilgang til dataa.", "The agent was denied access to the data."),
        ["win.unavailable.unsupported"] = T("Verdien støttes ikke av agenten på denne maskinen.", "Verdien blir ikkje støtta av agenten på denne maskina.", "The agent does not support this value on this computer."),
        ["win.unavailable.collector_timeout"] = T("Innsamlingen tok for lang tid.", "Innsamlinga tok for lang tid.", "The collection took too long."),
        ["win.unavailable.temporary_error"] = T("Dataene var midlertidig utilgjengelige; neste innsamling prøver igjen.", "Dataa var mellombels utilgjengelege; neste innsamling prøver igjen.", "The data was temporarily unavailable; the next collection retries."),
        ["win.applicability_input_missing"] = T("Dataene som avgjør om kontrollen gjelder, mangler i samme innsamling.", "Dataa som avgjer om kontrollen gjeld, manglar i same innsamling.", "The data that decides whether the check applies is missing from the same collection."),
        ["win.not_applicable.policy"] = T("Policyen krever ikke denne kontrollen.", "Policyen krev ikkje denne kontrollen.", "The policy does not require this check."),
        ["win.not_applicable.edition"] = T("Windows-utgaven støtter ikke kontrollen.", "Windows-utgåva støttar ikkje kontrollen.", "The Windows edition does not support the check."),
        ["win.evidence_time_invalid"] = T("Tidspunktet i dataene er ugyldig (i fremtiden).", "Tidspunktet i dataa er ugyldig (i framtida).", "The time in the data is invalid (in the future)."),
        ["win-001.pass"] = T("Ledig plass: {percent} % ({freeGiB} GiB).", "Ledig plass: {percent} % ({freeGiB} GiB).", "Free space: {percent}% ({freeGiB} GiB)."),
        ["win-001.fail.warning"] = T("Ledig plass er lav: {percent} % ({freeGiB} GiB).", "Ledig plass er låg: {percent} % ({freeGiB} GiB).", "Free space is low: {percent}% ({freeGiB} GiB)."),
        ["win-001.fail.critical"] = T("Ledig plass er kritisk lav: {percent} % ({freeGiB} GiB).", "Ledig plass er kritisk låg: {percent} % ({freeGiB} GiB).", "Free space is critically low: {percent}% ({freeGiB} GiB)."),
        ["win-002.pass"] = T("Systemdisken er fullt kryptert og beskyttelsen er på.", "Systemdisken er fullt kryptert og vernet er på.", "The system volume is fully encrypted and protection is on."),
        ["win-002.fail.suspended"] = T("Systemdisken er kryptert, men BitLocker-beskyttelsen er satt på pause.", "Systemdisken er kryptert, men BitLocker-vernet er sett på pause.", "The system volume is encrypted, but BitLocker protection is suspended."),
        ["win-002.fail.not_encrypted"] = T("Systemdisken er ikke fullt kryptert (status: {status}).", "Systemdisken er ikkje fullt kryptert (status: {status}).", "The system volume is not fully encrypted (status: {status})."),
        ["win-002.unknown.protection"] = T("Beskyttelsesstatusen til BitLocker er ukjent.", "Vernestatusen til BitLocker er ukjend.", "The BitLocker protection status is unknown."),
        ["win-002.unknown.encrypting"] = T("Krypteringen pågår ({percent} %); neste innsamling viser resultatet.", "Krypteringa pågår ({percent} %); neste innsamling viser resultatet.", "Encryption is in progress ({percent}%); the next collection shows the result."),
        ["win-003.pass"] = T("Et godkjent antivirusprogram er aktivt.", "Eit godkjent antivirusprogram er aktivt.", "An approved antivirus is active."),
        ["win-003.unknown.state"] = T("Statusen til et godkjent antivirusprogram er ukjent.", "Statusen til eit godkjent antivirusprogram er ukjend.", "The state of an approved antivirus is unknown."),
        ["win-003.fail.inactive"] = T("Godkjente antivirusprogrammer finnes, men ingen er aktive.", "Godkjende antivirusprogram finst, men ingen er aktive.", "Approved antivirus products exist, but none is active."),
        ["win-003.fail.none"] = T("Ingen godkjent antivirusprogram er installert.", "Inga godkjent antivirusprogram er installert.", "No approved antivirus is installed."),
        ["win-004.pass"] = T("Signaturene er {days} dager gamle.", "Signaturane er {days} dagar gamle.", "The signatures are {days} days old."),
        ["win-004.fail.warning"] = T("Signaturene er {days} dager gamle.", "Signaturane er {days} dagar gamle.", "The signatures are {days} days old."),
        ["win-004.fail.critical"] = T("Signaturene er {days} dager gamle, langt over grensen.", "Signaturane er {days} dagar gamle, langt over grensa.", "The signatures are {days} days old, far over the limit."),
        ["win-004.not_applicable.policy"] = T("Policyen godkjenner ikke Microsoft Defender.", "Policyen godkjenner ikkje Microsoft Defender.", "The policy does not approve Microsoft Defender."),
        ["win-004.not_applicable.defender"] = T("Microsoft Defender kjører ikke i normal modus på denne maskinen.", "Microsoft Defender køyrer ikkje i normal modus på denne maskina.", "Microsoft Defender does not run in normal mode on this computer."),
        ["win-005.pass"] = T("Alle påkrevde brannmurprofiler er på.", "Alle påkravde brannmurprofilar er på.", "All required firewall profiles are on."),
        ["win-005.pass.third_party"] = T("En godkjent brannmur fra tredjepart er aktiv.", "Ein godkjend brannmur frå tredjepart er aktiv.", "An approved third-party firewall is active."),
        ["win-005.unknown.state"] = T("Statusen til en godkjent brannmur er ukjent.", "Statusen til ein godkjend brannmur er ukjend.", "The state of an approved firewall is unknown."),
        ["win-005.fail"] = T("Profiler uten brannmur: {profiles}.", "Profilar utan brannmur: {profiles}.", "Profiles without a firewall: {profiles}."),
        ["win-006.pass"] = T("Windows Update har søkt nylig.", "Windows Update har søkt nyleg.", "Windows Update has searched recently."),
        ["win-006.fail"] = T("Siste vellykkede søk for {days} dager siden.", "Siste vellukka søk for {days} dagar sidan.", "Last successful search {days} days ago."),
        ["win-007.pass"] = T("Ingen langvarig omstart venter.", "Ingen langvarig omstart ventar.", "No long-lasting restart is pending."),
        ["win-007.pending"] = T("Omstart er påkrevd siden {since}, men under grensen.", "Omstart er påkravd sidan {since}, men under grensa.", "A restart has been required since {since}, but it is under the limit."),
        ["win-007.fail"] = T("Omstart har vært påkrevd i alle innsamlinger siden {since} ({days} dager). Siste oppstart: {lastBootAt}.", "Omstart har vore påkravd i alle innsamlingar sidan {since} ({days} dagar). Siste oppstart: {lastBootAt}.", "A restart was required in every collection since {since} ({days} days). Last boot: {lastBootAt}."),
        ["win-008.pass"] = T("Bare tillatte medlemmer i administratorgruppen.", "Berre tillatne medlemer i administratorgruppa.", "Only allowed members in the administrators group."),
        ["win-008.fail"] = T("Uventede medlemmer i administratorgruppen ({count}): {members}.", "Uventa medlemer i administratorgruppa ({count}): {members}.", "Unexpected members of the administrators group ({count}): {members}."),
        ["win-009.pass"] = T("Secure Boot er på.", "Secure Boot er på.", "Secure Boot is on."),
        ["win-009.fail"] = T("Secure Boot er ikke på (plattform: {platform}).", "Secure Boot er ikkje på (plattform: {platform}).", "Secure Boot is not on (platform: {platform})."),
        ["win-010.pass"] = T("Maskinen er koblet til riktig tenant ({joinType}).", "Maskina er kopla til rett tenant ({joinType}).", "The computer is joined to the expected tenant ({joinType})."),
        ["win-010.fail.not_joined"] = T("Maskinen er ikke koblet til Entra ({joinType}).", "Maskina er ikkje kopla til Entra ({joinType}).", "The computer is not joined to Entra ({joinType})."),
        ["win-010.fail.other_tenant"] = T("Maskinen er koblet til en annen tenant.", "Maskina er kopla til ein annan tenant.", "The computer is joined to another tenant."),
        ["win-010.unknown.tenant"] = T("Tenant-ID mangler i dataene.", "Tenant-ID manglar i dataa.", "The tenant ID is missing from the data."),
        ["win-010.unknown.no_expected"] = T("Policyen oppgir ikke forventet tenant.", "Policyen oppgir ikkje venta tenant.", "The policy does not name the expected tenant."),
        ["win-011.inventory"] = T("Operativsystemet er registrert.", "Operativsystemet er registrert.", "The operating system is recorded."),
        ["sys-001.fresh"] = T("Siste fullstendige innsamling er innenfor vinduet.", "Siste fullstendige innsamling er innanfor vindauget.", "The last full scan is inside the window."),
        ["sys-001.stale"] = T("Siste fullstendige innsamling er eldre enn vinduet, eller mangler.", "Siste fullstendige innsamling er eldre enn vindauget, eller manglar.", "The last full scan is older than the window, or missing."),
        ["sys.os_inventory_missing"] = T("Det finnes ingen fersk operativsystem-registrering fra agenten.", "Det finst inga fersk operativsystem-registrering frå agenten.", "There is no fresh operating system inventory from the agent."),
        ["sys-002.pass"] = T("Windows {version} får oppdateringer til {date}.", "Windows {version} får oppdateringar til {date}.", "Windows {version} is serviced until {date}."),
        ["sys-002.fail"] = T("Windows {version} fikk siste oppdatering {date}.", "Windows {version} fekk siste oppdatering {date}.", "Windows {version} was last serviced on {date}."),
        ["sys-002.fail.esu"] = T("Windows 10 22H2 fikk siste oppdatering {date}. Betalt ESU kan forlenge oppdateringene (registreres som akseptert risiko).", "Windows 10 22H2 fekk siste oppdatering {date}. Betalt ESU kan forlengje oppdateringane (registrerast som akseptert risiko).", "Windows 10 22H2 was last serviced on {date}. Paid ESU can extend updates (record it as an accepted risk)."),
        ["sys-002.fail.old"] = T("Windows build {build} er så gammel at oppdateringene er avsluttet.", "Windows build {build} er så gammal at oppdateringane er avslutta.", "Windows build {build} is so old that servicing has ended."),
        ["sys-002.unknown.matrix"] = T("Operativsystemet ligger utenfor det agenten dekker (arkitektur eller utgave).", "Operativsystemet ligg utanfor det agenten dekkjer (arkitektur eller utgåve).", "The operating system is outside what the agent covers (architecture or edition)."),
        ["sys-002.unknown.version"] = T("Versjonen finnes ikke i tabellen over levetid ennå.", "Versjonen finst ikkje i tabellen over levetid enno.", "The version is not in the lifecycle table yet."),
        ["sys-003.pass"] = T("Build {build}.{ubr} er på nivået til {level}; forventet måned er {expected}.", "Build {build}.{ubr} er på nivået til {level}; venta månad er {expected}.", "Build {build}.{ubr} is at the level of {level}; the expected month is {expected}."),
        ["sys-003.fail.warning"] = T("Build {build}.{ubr} er {behind} måned bak (nivå {level}, forventet {expected}). Mangler KB{kb}.", "Build {build}.{ubr} er {behind} månad bak (nivå {level}, venta {expected}). Manglar KB{kb}.", "Build {build}.{ubr} is {behind} month behind (level {level}, expected {expected}). Missing KB{kb}."),
        ["sys-003.fail.critical"] = T("Build {build}.{ubr} er {behind} måneder bak (nivå {level}, forventet {expected}). Mangler KB{kb}.", "Build {build}.{ubr} er {behind} månader bak (nivå {level}, venta {expected}). Manglar KB{kb}.", "Build {build}.{ubr} is {behind} months behind (level {level}, expected {expected}). Missing KB{kb}."),
        ["sys-003.unknown.branch"] = T("Build {build} finnes ikke i katalogen over utgivelser.", "Build {build} finst ikkje i katalogen over utgjevingar.", "Build {build} is not in the release catalog."),
        ["sys-003.unknown.stale"] = T("Katalogen over utgivelser er bare kontrollert til {verified}, men {expected} skulle vært kontrollert.", "Katalogen over utgjevingar er berre kontrollert til {verified}, men {expected} skulle vore kontrollert.", "The release catalog is verified only up to {verified}, but {expected} should have been verified."),
    };
}
