using System.Text.Json.Nodes;
using Sikkerheit.Agent.Collectors;

namespace Sikkerheit.Agent.Tests;

/// <summary>Evidence of the example development-package/examples/scan-batch.json for every check, as stub collectors.</summary>
public static class StubCollectors
{
    public static readonly string[] CheckIds =
        ["WIN-001", "WIN-002", "WIN-003", "WIN-004", "WIN-005", "WIN-006", "WIN-007", "WIN-008", "WIN-009", "WIN-010", "WIN-011"];

    public static JsonObject Evidence(string checkId) => checkId switch
    {
        "WIN-001" => (JsonObject)JsonNode.Parse("{\"totalBytes\": 256000000000, \"freeBytes\": 18000000000}")!,
        "WIN-002" => (JsonObject)JsonNode.Parse("{\"volumeStatus\": \"fully_encrypted\", \"protectionStatus\": \"off\", \"encryptionPercentage\": 100}")!,
        "WIN-003" => (JsonObject)JsonNode.Parse("{\"products\": [{\"provider\": \"Microsoft Defender Antivirus\", \"productState\": \"on\", \"statusSource\": \"defender\", \"rawState\": null}], \"defender\": {\"amRunningMode\": \"normal\", \"realTimeProtectionEnabled\": true}}")!,
        "WIN-004" => (JsonObject)JsonNode.Parse("{\"signatureLastUpdatedAt\": \"2026-10-14T08:00:00Z\"}")!,
        "WIN-005" => (JsonObject)JsonNode.Parse("{\"domainEnabled\": true, \"privateEnabled\": true, \"publicEnabled\": true, \"firewallProducts\": []}")!,
        "WIN-006" => (JsonObject)JsonNode.Parse("{\"lastSearchSuccessAt\": \"2026-10-14T06:15:00Z\", \"lastInstallSuccessAt\": \"2026-10-14T03:40:00Z\", \"wsusConfigured\": false}")!,
        "WIN-007" => (JsonObject)JsonNode.Parse("{\"rebootRequired\": false, \"lastBootAt\": \"2026-10-14T07:30:00Z\"}")!,
        "WIN-008" => (JsonObject)JsonNode.Parse("{\"members\": [{\"sid\": \"S-1-5-21-1000-2000-3000-500\", \"kind\": \"builtin_administrator\", \"relativeId\": 500}, {\"sid\": \"S-1-12-1-1111111111-2222222222-3333333333-4444444444\", \"kind\": \"entra\", \"relativeId\": null}], \"membershipScope\": \"direct_members\"}")!,
        "WIN-009" => (JsonObject)JsonNode.Parse("{\"enabled\": true, \"platform\": \"uefi\"}")!,
        "WIN-010" => (JsonObject)JsonNode.Parse("{\"joinType\": \"entra_joined\", \"tenantId\": \"22222222-2222-4222-8222-222222222222\", \"entraDeviceId\": \"33333333-3333-4333-8333-333333333333\"}")!,
        "WIN-011" => (JsonObject)JsonNode.Parse("{\"editionId\": \"Professional\", \"displayVersion\": \"25H2\", \"build\": 26200, \"ubr\": 9711, \"architecture\": \"x64\"}")!,
        _ => throw new ArgumentException(checkId),
    };

    public static List<ICollector> All() =>
        [.. CheckIds.Select(id => (ICollector)new StubCollector(id, _ => CollectorOutcome.Collected(Evidence(id))))];

    public static List<ICollector> With(string checkId, Func<CollectionContext, CollectorOutcome> collect) =>
        [.. CheckIds.Select(id => id == checkId ? new StubCollector(id, collect) : new StubCollector(id, _ => CollectorOutcome.Collected(Evidence(id))))];
}
