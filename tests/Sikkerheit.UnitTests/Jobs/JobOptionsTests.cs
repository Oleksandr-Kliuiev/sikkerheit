using Sikkerheit.Host.Jobs;

namespace Sikkerheit.UnitTests.Jobs;

public sealed class JobOptionsTests
{
    [Theory]
    [InlineData(0, 2)]
    [InlineData(9, 2)]
    [InlineData(8, 0)]
    [InlineData(8, 9)]
    public void Reject_unbounded_or_disabled_lanes(int collection, int maintenance) => Assert.Throws<InvalidOperationException>(
        () => new JobExecutionOptions { CollectionConcurrency = collection, MaintenanceConcurrency = maintenance }.Validate());

    [Fact]
    public void Default_admission_matches_the_capacity_model()
    {
        var options = new JobExecutionOptions();
        options.Validate();
        Assert.Equal(8, options.CollectionConcurrency);
        Assert.Equal(2, options.MaintenanceConcurrency);
    }
}
