using System.Text.Json;

namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Texts of rules in nb, nn and en (01 «Язык портала и отчёта»): title and recommendation per check, explanation per
/// outcome key. Drafts for review by a person who approves the texts (question 9 in 08).
/// </summary>
public static class Texts
{
    public static readonly string[] Languages = ["nb", "nn", "en"];

    /// <summary>Accept-Language → nb, nn or en; anything else falls back to nb without an error.</summary>
    public static string Language(string? acceptLanguage)
    {
        if (string.IsNullOrWhiteSpace(acceptLanguage) || acceptLanguage.Length > 35)
        {
            return "nb";
        }
        foreach (var part in acceptLanguage.Split(','))
        {
            var tag = part.Split(';')[0].Trim().ToLowerInvariant();
            var primary = tag.Split('-')[0];
            if (primary is "nb" or "nn" or "en")
            {
                return primary;
            }
            if (primary == "no")
            {
                return "nb";
            }
        }
        return "nb";
    }

    private static readonly Dictionary<string, (string Nb, string Nn, string En)> Titles = new(StringComparer.Ordinal)
    {
        ["M365-001"] = ("Bruker uten registrert MFA-metode", "Brukar utan registrert MFA-metode", "User without a registered MFA method"),
        ["M365-002"] = ("Administrator uten registrert MFA-metode", "Administrator utan registrert MFA-metode", "Administrator without a registered MFA method"),
        ["M365-003"] = ("MFA er ikke påkrevd for alle brukere", "MFA er ikkje kravd for alle brukarar", "MFA is not required for all users"),
        ["M365-004"] = ("Eldre autentisering er ikke blokkert", "Eldre autentisering er ikkje blokkert", "Legacy authentication is not blocked"),
        ["M365-005"] = ("Antall globale administratorer er utenfor anbefalt område", "Talet på globale administratorar er utanfor tilrådd område", "Number of global administrators is outside the recommended range"),
        ["M365-006"] = ("Brukere kan gi samtykke til apper", "Brukarar kan gje samtykke til appar", "Users can consent to applications"),
        ["M365-007"] = ("Inaktiv brukerkonto", "Inaktiv brukarkonto", "Inactive user account"),
    };

    private static readonly Dictionary<string, (string Nb, string Nn, string En)> Recommendations = new(StringComparer.Ordinal)
    {
        ["M365-001"] = ("Be brukeren registrere Microsoft Authenticator eller en FIDO2-nøkkel.",
            "Be brukaren registrere Microsoft Authenticator eller ein FIDO2-nøkkel.",
            "Ask the user to register Microsoft Authenticator or a FIDO2 key."),
        ["M365-002"] = ("Registrer en sterk MFA-metode for administratoren, helst FIDO2. Gjest med administratorrolle bør få tilgang via GDAP eller egen konto i tenanten.",
            "Registrer ein sterk MFA-metode for administratoren, helst FIDO2. Gjest med administratorrolle bør få tilgang via GDAP eller eigen konto i tenanten.",
            "Register a strong MFA method for the administrator, preferably FIDO2. A guest with an administrator role should get access through GDAP or an account in the tenant."),
        ["M365-003"] = ("Slå på Security Defaults eller en betinget tilgangspolicy som krever MFA for alle brukere og alle apper.",
            "Slå på Security Defaults eller ein policy for vilkårsbunden tilgang som krev MFA for alle brukarar og alle appar.",
            "Turn on Security Defaults or a Conditional Access policy that requires MFA for all users and all applications."),
        ["M365-004"] = ("Blokker eldre autentisering med Security Defaults eller en betinget tilgangspolicy.",
            "Blokker eldre autentisering med Security Defaults eller ein policy for vilkårsbunden tilgang.",
            "Block legacy authentication with Security Defaults or a Conditional Access policy."),
        ["M365-005"] = ("Ha to til fire aktive globale administratorer, inkludert en nødkonto. Fjern rollen fra deaktiverte kontoer.",
            "Ha to til fire aktive globale administratorar, medrekna ein naudkonto. Fjern rolla frå deaktiverte kontoar.",
            "Keep two to four enabled global administrators, including an emergency access account. Remove the role from disabled accounts."),
        ["M365-006"] = ("Tillat bare samtykke for verifiserte utgivere med lav påvirkning, eller slå av brukersamtykke.",
            "Tillat berre samtykke for verifiserte utgjevarar med låg påverknad, eller slå av brukarsamtykke.",
            "Allow consent only for verified publishers with low-impact permissions, or turn user consent off."),
        ["M365-007"] = ("Vurder å deaktivere kontoen eller bekreft at den fortsatt trengs.",
            "Vurder å deaktivere kontoen eller stadfest at han framleis trengst.",
            "Consider disabling the account or confirm that it is still needed."),
    };

    private static readonly Dictionary<string, (string Nb, string Nn, string En)> Explanations = new(StringComparer.Ordinal)
    {
        ["common.missing_observation"] = ("Ingen data for denne kontrollen i siste innsamling.", "Ingen data for denne kontrollen i siste innsamling.", "No data for this check in the last collection."),
        ["common.unavailable.permission_denied"] = ("Microsoft 365 nektet tilgang til dataene (manglende rettighet).", "Microsoft 365 nekta tilgang til dataa (manglande rett).", "Microsoft 365 denied access to the data (missing permission)."),
        ["common.unavailable.temporary_error"] = ("Dataene var midlertidig utilgjengelige; neste innsamling prøver igjen.", "Dataa var mellombels utilgjengelege; neste innsamling prøver igjen.", "The data was temporarily unavailable; the next collection retries."),
        ["common.unavailable.license_missing"] = ("Tenanten mangler lisensen som trengs for disse dataene.", "Tenanten manglar lisensen som trengst for desse dataa.", "The tenant lacks the license these data require."),
        ["common.unavailable.partial_data"] = ("Dataene var ufullstendige, så resultatet kan ikke fastslås.", "Dataa var ufullstendige, så resultatet kan ikkje fastslåast.", "The data was incomplete, so the result cannot be determined."),
        ["common.not_implemented"] = ("Kontrollen er ikke tilgjengelig ennå.", "Kontrollen er ikkje tilgjengeleg enno.", "The check is not available yet."),
        ["m365-001.pass"] = ("Registrerte metoder: {methods}. Minst én er en MFA-metode. Registrering viser ikke om MFA kreves ved pålogging (se M365-003).", "Registrerte metodar: {methods}. Minst éin er ein MFA-metode. Registrering viser ikkje om MFA er kravd ved pålogging (sjå M365-003).", "Registered methods: {methods}. At least one is an MFA method. Registration does not show whether MFA is required at sign-in (see M365-003)."),
        ["m365-001.fail"] = ("Registrerte metoder: {methods}. Ingen av dem er en MFA-metode. Maskinvare-OATH-tokener vises ikke ennå.", "Registrerte metodar: {methods}. Ingen av dei er ein MFA-metode. Maskinvare-OATH-token blir ikkje viste enno.", "Registered methods: {methods}. None is an MFA method. Hardware OATH tokens are not visible yet."),
        ["m365-001.not_applicable.disabled"] = ("Kontoen er deaktivert.", "Kontoen er deaktivert.", "The account is disabled."),
        ["m365-001.not_applicable.guest"] = ("Gjestekontoer vurderes ikke: metodene deres ligger i hjemmetenanten.", "Gjestekontoar blir ikkje vurderte: metodane deira ligg i heimetenanten.", "Guest accounts are not assessed: their methods live in their home tenant."),
        ["m365-001.not_applicable.excluded"] = ("Kontoen er unntatt i policyen (nødtilgang eller tjenestekonto).", "Kontoen er unnateken i policyen (naudtilgang eller tenestekonto).", "The account is excluded by policy (emergency access or service account)."),
        ["m365-001.not_applicable.sync_account"] = ("Synkroniseringskontoen til Entra Connect kan ikke ha MFA.", "Synkroniseringskontoen til Entra Connect kan ikkje ha MFA.", "The Entra Connect synchronization account cannot have MFA."),
        ["m365-002.pass"] = ("Administratoren har en MFA-metode: {methods}.", "Administratoren har ein MFA-metode: {methods}.", "The administrator has an MFA method: {methods}."),
        ["m365-002.fail"] = ("Administratoren har ingen MFA-metode. Registrerte metoder: {methods}.", "Administratoren har ingen MFA-metode. Registrerte metodar: {methods}.", "The administrator has no MFA method. Registered methods: {methods}."),
        ["m365-002.fail.guest"] = ("En gjest har en privilegert rolle; MFA-metodene kan ikke bekreftes her.", "Ein gjest har ei privilegert rolle; MFA-metodane kan ikkje stadfestast her.", "A guest holds a privileged role; their MFA methods cannot be confirmed here."),
        ["m365-002.not_applicable.no_role"] = ("Kontoen har ikke lenger en privilegert rolle.", "Kontoen har ikkje lenger ei privilegert rolle.", "The account no longer holds a privileged role."),
        ["m365-002.not_applicable.disabled"] = ("Administratorkontoen er deaktivert.", "Administratorkontoen er deaktivert.", "The administrator account is disabled."),
        ["m365-003.pass.security_defaults"] = ("Security Defaults er på. De krever MFA «ved behov», ikke ved hver pålogging.", "Security Defaults er på. Dei krev MFA «ved behov», ikkje ved kvar pålogging.", "Security Defaults are on. They require MFA when needed, not at every sign-in."),
        ["m365-003.pass.conditional_access"] = ("En aktiv policy for betinget tilgang krever MFA for alle brukere og apper ({policyId}).", "Ein aktiv policy for vilkårsbunden tilgang krev MFA for alle brukarar og appar ({policyId}).", "An active Conditional Access policy requires MFA for all users and applications ({policyId})."),
        ["m365-003.pass.per_user_mfa"] = ("MFA per bruker er håndhevet for alle brukere.", "MFA per brukar er handheva for alle brukarar.", "Per-user MFA is enforced for all users."),
        ["m365-003.unknown.per_user_enabled"] = ("MFA per bruker er slått på, men ikke håndhevet for alle; håndheving er ikke bekreftet.", "MFA per brukar er slått på, men ikkje handheva for alle; handheving er ikkje stadfesta.", "Per-user MFA is enabled but not enforced for everyone; enforcement is not confirmed."),
        ["m365-003.unknown.conditional_policies"] = ("Policyer krever MFA, men ingen gjelder ubetinget for alle; dekningen kan ikke bevises.", "Policyar krev MFA, men ingen gjeld utan vilkår for alle; dekninga kan ikkje provast.", "Policies require MFA, but none applies unconditionally to everyone; coverage cannot be proven."),
        ["m365-003.unknown.per_user_off"] = ("Håndheving av MFA kan ikke bekreftes. Slå på Security Defaults eller en policy for alle.", "Handheving av MFA kan ikkje stadfestast. Slå på Security Defaults eller ein policy for alle.", "MFA enforcement cannot be confirmed. Turn on Security Defaults or a policy for everyone."),
        ["m365-003.fail"] = ("Security Defaults er av, ingen policy krever MFA for alle, og MFA per bruker mangler for noen brukere.", "Security Defaults er av, ingen policy krev MFA for alle, og MFA per brukar manglar for nokre brukarar.", "Security Defaults are off, no policy requires MFA for everyone, and per-user MFA is missing for some users."),
        ["m365-004.pass.security_defaults"] = ("Security Defaults blokkerer eldre autentisering.", "Security Defaults blokkerer eldre autentisering.", "Security Defaults block legacy authentication."),
        ["m365-004.pass.conditional_access"] = ("En policy blokkerer eldre autentisering for alle.", "Ein policy blokkerer eldre autentisering for alle.", "A policy blocks legacy authentication for everyone."),
        ["m365-004.fail"] = ("Ingen policy blokkerer eldre autentisering, og Security Defaults er av.", "Ingen policy blokkerer eldre autentisering, og Security Defaults er av.", "No policy blocks legacy authentication, and Security Defaults are off."),
        ["m365-004.unknown.no_conditional_access"] = ("Uten betinget tilgang og med Security Defaults av kan blokkeringen ikke bekreftes.", "Utan vilkårsbunden tilgang og med Security Defaults av kan blokkeringa ikkje stadfestast.", "Without Conditional Access and with Security Defaults off, blocking cannot be confirmed."),
        ["m365-005.pass"] = ("{count} aktive globale administratorer.", "{count} aktive globale administratorar.", "{count} enabled global administrators."),
        ["m365-005.fail.too_few"] = ("Bare {count} aktiv global administrator. Én administrator er et enkelt feilpunkt.", "Berre {count} aktiv global administrator. Éin administrator er eit einskild feilpunkt.", "Only {count} enabled global administrator. One administrator is a single point of failure."),
        ["m365-005.fail.too_many"] = ("{count} aktive globale administratorer er flere enn anbefalt.", "{count} aktive globale administratorar er fleire enn tilrådd.", "{count} enabled global administrators is more than recommended."),
        ["m365-005.unknown.groups"] = ("Medlemmene av en gruppe med rollen kunne ikke leses.", "Medlemene av ei gruppe med rolla kunne ikkje lesast.", "Members of a group holding the role could not be read."),
        ["m365-006.fail.legacy"] = ("Brukere kan gi samtykke til alle apper ({policies}).", "Brukarar kan gje samtykke til alle appar ({policies}).", "Users can consent to any application ({policies})."),
        ["m365-006.fail.not_allowed"] = ("Samtykkepolicyen er ikke tillatt av kundens policy ({policies}).", "Samtykkepolicyen er ikkje tillaten av policyen til kunden ({policies}).", "The consent policy is not allowed by the customer policy ({policies})."),
        ["m365-006.pass.disabled"] = ("Brukersamtykke til apper er slått av.", "Brukarsamtykke til appar er slått av.", "User consent to applications is turned off."),
        ["m365-006.pass.allowed"] = ("Bare tillatte samtykkepolicyer er i bruk ({policies}).", "Berre tillatne samtykkepolicyar er i bruk ({policies}).", "Only allowed consent policies are in use ({policies})."),
        ["m365-006.unknown.custom"] = ("En egendefinert samtykkepolicy er i bruk; den må vurderes manuelt.", "Ein eigendefinert samtykkepolicy er i bruk; han må vurderast manuelt.", "A custom consent policy is in use; it needs a manual review."),
    };

    public static string Title(string checkId, string language) => Pick(Titles, checkId, language) ?? checkId;

    public static string Recommendation(string checkId, string language) => Pick(Recommendations, checkId, language) ?? "";

    /// <summary>Explanation from the basis snapshot: key and arguments; unknown keys fall back to the key itself.</summary>
    public static string Explanation(string basisSnapshot, string language)
    {
        using var document = JsonDocument.Parse(basisSnapshot);
        var root = document.RootElement;
        var key = root.TryGetProperty("explanation", out var k) ? k.GetString() ?? "" : "";
        var text = Pick(Explanations, key, language) ?? key;
        if (root.TryGetProperty("arguments", out var args) && args.ValueKind == JsonValueKind.Object)
        {
            foreach (var argument in args.EnumerateObject())
            {
                text = text.Replace("{" + argument.Name + "}", argument.Value.GetString(), StringComparison.Ordinal);
            }
        }
        return text.Length > 2000 ? text[..2000] : text;
    }

    public static bool HasAllLanguages(string key) => Explanations.ContainsKey(key);

    /// <summary>Title and recommendation exist in the language (a report without them fails with translation_missing).</summary>
    public static bool HasCheckTexts(string checkId, string language) =>
        !string.IsNullOrWhiteSpace(Pick(Titles, checkId, language)) && !string.IsNullOrWhiteSpace(Pick(Recommendations, checkId, language));

    public static IEnumerable<string> ExplanationKeys => Explanations.Keys;

    private static string? Pick(Dictionary<string, (string Nb, string Nn, string En)> table, string key, string language) =>
        table.TryGetValue(key, out var text) ? language switch { "nn" => text.Nn, "en" => text.En, _ => text.Nb } : null;
}
