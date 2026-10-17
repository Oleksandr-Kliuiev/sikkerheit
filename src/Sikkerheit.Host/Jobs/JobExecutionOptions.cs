namespace Sikkerheit.Host.Jobs;

/// <summary>Separate bounded lanes keep long Graph collections from blocking reports and maintenance.</summary>
public sealed class JobExecutionOptions
{
    public int CollectionConcurrency { get; init; } = 8;
    public int MaintenanceConcurrency { get; init; } = 2;

    public void Validate()
    {
        if (CollectionConcurrency is < 1 or > 8 || MaintenanceConcurrency is < 1 or > 8)
        {
            throw new InvalidOperationException("Jobs:CollectionConcurrency and Jobs:MaintenanceConcurrency must be between 1 and 8");
        }
    }
}
