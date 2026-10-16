using System.Text;
using Microsoft.EntityFrameworkCore;

namespace Sikkerheit.Host.Data;

/// <summary>EF Core mapping onto the SQL schema of Data/Migrations; the schema itself is not managed by EF.</summary>
public sealed class SikkerheitDb(DbContextOptions<SikkerheitDb> options) : DbContext(options)
{
    public DbSet<StaffUser> StaffUsers => Set<StaffUser>();
    public DbSet<StaffSession> StaffSessions => Set<StaffSession>();
    public DbSet<OrganizationTombstone> OrganizationTombstones => Set<OrganizationTombstone>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<PolicyRevision> PolicyRevisions => Set<PolicyRevision>();
    public DbSet<TenantConnection> TenantConnections => Set<TenantConnection>();
    public DbSet<IdempotencyRecord> IdempotencyRecords => Set<IdempotencyRecord>();
    public DbSet<CollectionRun> CollectionRuns => Set<CollectionRun>();
    public DbSet<Subject> Subjects => Set<Subject>();
    public DbSet<Observation> Observations => Set<Observation>();
    public DbSet<Assessment> Assessments => Set<Assessment>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<FindingEvent> FindingEvents => Set<FindingEvent>();
    public DbSet<RiskDecision> RiskDecisions => Set<RiskDecision>();
    public DbSet<Report> Reports => Set<Report>();
    public DbSet<OrganizationExport> OrganizationExports => Set<OrganizationExport>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<EnrollmentKey> EnrollmentKeys => Set<EnrollmentKey>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<DevicePresence> DevicePresences => Set<DevicePresence>();
    public DbSet<RevokedInstallation> RevokedInstallations => Set<RevokedInstallation>();
    public DbSet<Enrollment> Enrollments => Set<Enrollment>();
    public DbSet<ScanBatch> ScanBatches => Set<ScanBatch>();
    public DbSet<ScanRequest> ScanRequests => Set<ScanRequest>();
    public DbSet<AgentChallenge> AgentChallenges => Set<AgentChallenge>();
    public DbSet<AgentSession> AgentSessions => Set<AgentSession>();
    public DbSet<WindowsRelease> WindowsReleases => Set<WindowsRelease>();
    public DbSet<WindowsReleaseMonth> WindowsReleaseMonths => Set<WindowsReleaseMonth>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<StaffUser>(e => { e.ToTable("staff_user"); e.HasKey(x => x.EntraUserId); });
        model.Entity<StaffSession>(e => { e.ToTable("staff_session"); e.HasKey(x => x.IdHash); });
        model.Entity<OrganizationTombstone>(e => { e.ToTable("organization_tombstone"); e.HasKey(x => x.Id); });
        model.Entity<Job>(e => { e.ToTable("job"); e.HasKey(x => x.Id); });
        model.Entity<Organization>(e => { e.ToTable("organization"); e.HasKey(x => x.Id); });
        model.Entity<PolicyRevision>(e =>
        {
            e.ToTable("policy_revision");
            e.HasKey(x => new { x.OrganizationId, x.Version });
            e.Property(x => x.Configuration).HasColumnType("jsonb");
        });
        model.Entity<TenantConnection>(e =>
        {
            e.ToTable("tenant_connection");
            e.HasKey(x => x.OrganizationId);
            e.Property(x => x.Capabilities).HasColumnType("jsonb");
        });
        model.Entity<IdempotencyRecord>(e =>
        {
            e.ToTable("idempotency_record");
            e.HasKey(x => new { x.OrganizationId, x.OperationId, x.Key });
        });
        model.Entity<CollectionRun>(e =>
        {
            e.ToTable("collection_run");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.Capabilities).HasColumnType("jsonb");
        });
        model.Entity<Subject>(e => { e.ToTable("subject"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<Observation>(e =>
        {
            e.ToTable("observation");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.Evidence).HasColumnType("jsonb");
        });
        model.Entity<Assessment>(e =>
        {
            e.ToTable("assessment");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.BasisSnapshot).HasColumnType("jsonb");
        });
        model.Entity<Finding>(e => { e.ToTable("finding"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<FindingEvent>(e => { e.ToTable("finding_event"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<RiskDecision>(e => { e.ToTable("risk_decision"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<Report>(e =>
        {
            e.ToTable("report");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.Snapshot).HasColumnType("jsonb");
        });
        model.Entity<OrganizationExport>(e =>
        {
            e.ToTable("organization_export");
            e.HasKey(x => new { x.OrganizationId, x.Id });
        });
        model.Entity<AuditEvent>(e =>
        {
            e.ToTable("audit_event");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.Details).HasColumnType("jsonb");
        });
        model.Entity<EnrollmentKey>(e => { e.ToTable("enrollment_key"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<Device>(e =>
        {
            e.ToTable("device");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.PublicKeyJwk).HasColumnType("jsonb");
            e.Property(x => x.ConflictPublicKeyJwk).HasColumnType("jsonb");
            e.Property(x => x.Telemetry).HasColumnType("jsonb");
        });
        model.Entity<DevicePresence>(e => { e.ToTable("device_presence"); e.HasKey(x => new { x.OrganizationId, x.DeviceId, x.Day }); });
        model.Entity<RevokedInstallation>(e => { e.ToTable("revoked_installation"); e.HasKey(x => new { x.OrganizationId, x.InstallationId }); });
        model.Entity<Enrollment>(e =>
        {
            e.ToTable("enrollment");
            e.HasKey(x => new { x.OrganizationId, x.Id });
            e.Property(x => x.Response).HasColumnType("jsonb");
        });
        model.Entity<ScanBatch>(e => { e.ToTable("scan_batch"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<ScanRequest>(e => { e.ToTable("scan_request"); e.HasKey(x => new { x.OrganizationId, x.Id }); });
        model.Entity<AgentChallenge>(e => { e.ToTable("agent_challenge"); e.HasKey(x => x.NonceHash); });
        model.Entity<AgentSession>(e => { e.ToTable("agent_session"); e.HasKey(x => x.TokenHash); });
        model.Entity<WindowsRelease>(e => { e.ToTable("windows_release"); e.HasKey(x => new { x.Product, x.BranchBuild, x.Ubr }); });
        model.Entity<WindowsReleaseMonth>(e => { e.ToTable("windows_release_month"); e.HasKey(x => x.SecurityMonth); });

        // Relationships mirror the foreign keys of the schema so that EF orders inserts correctly.
        model.Entity<StaffSession>().HasOne<StaffUser>().WithMany().HasForeignKey(x => x.EntraUserId);
        model.Entity<PolicyRevision>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<TenantConnection>().HasOne<Organization>().WithOne().HasForeignKey<TenantConnection>(x => x.OrganizationId);
        model.Entity<IdempotencyRecord>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<CollectionRun>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<Subject>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<Observation>().HasOne<Subject>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.SubjectId });
        model.Entity<Observation>().HasOne<CollectionRun>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.CollectionRunId });
        model.Entity<Assessment>().HasOne<Subject>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.SubjectId });
        model.Entity<Assessment>().HasOne<Observation>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.ObservationId });
        model.Entity<Finding>().HasOne<Subject>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.SubjectId });
        model.Entity<FindingEvent>().HasOne<Finding>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.FindingId });
        model.Entity<RiskDecision>().HasOne<Finding>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.FindingId });
        model.Entity<RiskDecision>().HasOne<FindingEvent>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.FindingEventId });
        model.Entity<Report>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<OrganizationExport>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<AuditEvent>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<EnrollmentKey>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<Device>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<DevicePresence>().HasOne<Device>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.DeviceId });
        model.Entity<RevokedInstallation>().HasOne<Organization>().WithMany().HasForeignKey(x => x.OrganizationId);
        model.Entity<ScanBatch>().HasOne<Device>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.DeviceId });
        model.Entity<ScanRequest>().HasOne<Device>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.DeviceId });
        model.Entity<Enrollment>().HasOne<Device>().WithMany().HasForeignKey(x => new { x.OrganizationId, x.DeviceId });

        foreach (var entity in model.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                property.SetColumnName(SnakeCase(property.Name));
            }
        }
    }

    internal static string SnakeCase(string name)
    {
        var builder = new StringBuilder(name.Length + 8);
        for (var i = 0; i < name.Length; i++)
        {
            var c = name[i];
            if (char.IsUpper(c))
            {
                if (i > 0)
                {
                    builder.Append('_');
                }
                builder.Append(char.ToLowerInvariant(c));
            }
            else
            {
                builder.Append(c);
            }
        }
        return builder.ToString();
    }
}
