namespace Sikkerheit.Agent.Tests;

/// <summary>A negative test of a record of invariants.json with enforcement "agent" (WP-09). The record id is INV-xxx.</summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class InvariantAttribute(string id) : Attribute
{
    public string Id { get; } = id;
}
