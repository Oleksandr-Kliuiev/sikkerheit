namespace Sikkerheit.Host.Assessment;

/// <summary>
/// Display names of built-in Microsoft Entra role templates for explanations. The privileged roles of policy v1 follow
/// the table of 03 «Правило M365-001 и M365-002»; a template without a name here is shown by its id.
/// </summary>
public static class RoleNames
{
    private static readonly Dictionary<string, string> Names = new(StringComparer.OrdinalIgnoreCase)
    {
        ["62e90394-69f5-4237-9190-012177145e10"] = "Global Administrator",
        ["e8611ab8-c189-46e8-94e1-60213ab1f814"] = "Privileged Role Administrator",
        ["7be44c8a-adaf-4e2a-84d6-ab2649e08a13"] = "Privileged Authentication Administrator",
        ["194ae4cb-b126-40b2-bd5b-6091b380977d"] = "Security Administrator",
        ["b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"] = "Conditional Access Administrator",
        ["29232cdf-9323-42fd-ade2-1d097af3e4de"] = "Exchange Administrator",
        ["f28a1f50-f6e7-4571-818b-6a12f2af6b6c"] = "SharePoint Administrator",
        ["fe930be7-5e62-47db-91af-98c3a49a38b1"] = "User Administrator",
        ["c4e39bd9-1100-46d3-8c65-fb160da0071f"] = "Authentication Administrator",
        ["0526716b-113d-4c15-b2c8-68e3c22b9f80"] = "Authentication Policy Administrator",
        ["966707d0-3269-4727-9be2-8c3a10f19b9d"] = "Password Administrator",
        ["9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"] = "Application Administrator",
        ["158c047a-c907-4556-b7ef-446551a6b5f7"] = "Cloud Application Administrator",
        ["3a2c62db-5318-420d-8d74-23affee5d9d5"] = "Intune Administrator",
        ["729827e3-9c14-49f7-bb1b-9608f156bbb8"] = "Helpdesk Administrator",
        ["b0f54661-2d74-4c50-afa3-1ec803f12efe"] = "Billing Administrator",
        ["9360feb5-f418-4baa-8175-e2a00bac4301"] = "Directory Writers",
        ["e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8"] = "Partner Tier2 Support",
        ["d29b2b05-8046-44ba-8758-1e26182fcf32"] = "Directory Synchronization Accounts",
        ["f2ef992c-3afb-46b9-b7cf-a126ee74c451"] = "Global Reader",
        ["88d8e3e3-8f55-4a1e-953a-9b9898b8876b"] = "Directory Readers",
        ["5d6b6bb7-de71-4623-b4af-96380a352509"] = "Security Reader",
        ["4a5d8f65-41da-4de4-8968-e035b65339cf"] = "Reports Reader",
        ["69091246-20e8-4a56-aa4d-066075b2a7a8"] = "Teams Administrator",
        ["4d6ac14f-3453-41d0-bef9-a3e0c569773a"] = "License Administrator",
        ["fdd7a751-b60b-444a-984c-02652fe8fa1c"] = "Groups Administrator",
        ["17315797-102d-40b4-93e0-432062caca18"] = "Compliance Administrator",
        ["f023fd81-a637-4b56-95fd-791ac0226033"] = "Service Support Administrator",
        ["95e79109-95c0-4d8e-aee3-d01accf2d47b"] = "Guest Inviter",
    };

    public static string Name(string templateId) => Names.GetValueOrDefault(templateId, templateId);
}
