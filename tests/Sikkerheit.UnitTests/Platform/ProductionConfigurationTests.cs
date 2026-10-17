using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.UnitTests.Platform;

public sealed class ProductionConfigurationTests
{
    private sealed class Environment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";
        public string ApplicationName { get; set; } = "Sikkerheit";
        public string ContentRootPath { get; set; } = "/tmp";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static Dictionary<string, string?> Settings() => ProductionConfiguration.RequiredSettings.ToDictionary(
        key => key, key => (string?)(key.EndsWith(":Key", StringComparison.Ordinal) || key == "Agents:NonceKey"
            ? Convert.ToBase64String(new byte[32]) : key == "Hosting:PortalHosts:0" ? "portal.test" : "agent.test"));

    [Fact]
    public void Every_required_setting_is_checked_before_any_network_access()
    {
        foreach (var name in ProductionConfiguration.RequiredSettings)
        {
            var settings = Settings();
            settings.Remove(name);
            var error = Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(
                new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new Environment()));
            Assert.Contains(name, error.Message, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("@Microsoft.KeyVault(VaultName=test;SecretName=agents-nonce-key)")]
    [InlineData("not-a-secret-value")]
    [InlineData("eA==")]
    public void Unresolved_or_invalid_keys_fail_without_disclosing_the_value(string value)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Agents:NonceKey"] = value }).Build();
        var error = Assert.Throws<InvalidOperationException>(() =>
            ProductionConfiguration.HmacKey(configuration, new Environment(), "Agents:NonceKey"));
        Assert.Contains("Agents:NonceKey", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(value, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void The_same_key_survives_a_restart_and_development_can_generate_one()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(Settings()).Build();
        ProductionConfiguration.Validate(configuration, new Environment());
        Assert.Equal(ProductionConfiguration.HmacKey(configuration, new Environment(), "Agents:NonceKey"),
            ProductionConfiguration.HmacKey(configuration, new Environment(), "Agents:NonceKey"));
        Assert.Equal(32, ProductionConfiguration.HmacKey(new ConfigurationBuilder().Build(),
            new Environment { EnvironmentName = "Testing" }, "Agents:NonceKey").Length);
    }

    [Fact]
    public void Shared_hostnames_are_only_allowed_for_staging_smoke_tests()
    {
        var settings = Settings();
        settings["Hosting:AgentHosts:0"] = "portal.test";
        Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new Environment()));
        settings["WEBSITE_SLOT_NAME"] = "staging";
        ProductionConfiguration.Validate(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new Environment());
    }

    [Theory]
    [InlineData("Hosting:AgentHosts:0", "https://agent.test")]
    [InlineData("Hosting:AgentHosts:0", "agent..test")]
    [InlineData("Agents:MinimumAgentVersion", "latest")]
    [InlineData("Agents:MinimumAgentVersion", "999999999999999.0.0")]
    public void Malformed_hostnames_and_versions_fail_before_startup(string name, string value)
    {
        var settings = Settings();
        settings[name] = value;
        Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(
            new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new Environment()));
    }
}
