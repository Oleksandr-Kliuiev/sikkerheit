using Microsoft.Data.Sqlite;

namespace Sikkerheit.Agent.Storage;

/// <summary>SQLite file in the data directory: the buffer of batches and the key-value state of the agent.</summary>
public sealed class AgentDatabase
{
    private readonly string _connectionString;
    private readonly Lock _gate = new();

    public AgentDatabase(string path)
    {
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString();
        Execute("""
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS batch (
              scan_id TEXT PRIMARY KEY,
              sequence INTEGER NOT NULL,
              completed_at TEXT NOT NULL,
              body BLOB NOT NULL,
              bytes INTEGER NOT NULL,
              server_errors INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS batch_sequence ON batch (sequence);
            CREATE TABLE IF NOT EXISTS kv (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """);
    }

    /// <summary>Runs the action in one transaction under a single writer lock.</summary>
    public T InTransaction<T>(Func<SqliteConnection, SqliteTransaction, T> action)
    {
        lock (_gate)
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            var result = action(connection, transaction);
            transaction.Commit();
            return result;
        }
    }

    public void InTransaction(Action<SqliteConnection, SqliteTransaction> action) =>
        InTransaction((connection, transaction) =>
        {
            action(connection, transaction);
            return 0;
        });

    private void Execute(string sql)
    {
        lock (_gate)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            command.ExecuteNonQuery();
        }
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA synchronous = FULL;";
        command.ExecuteNonQuery();
        return connection;
    }
}

/// <summary>Small persistent state: device id, state of the automaton, counters of the telemetry, the stored configuration.</summary>
public sealed class AgentStateStore(AgentDatabase database)
{
    public string? Get(string key) => database.InTransaction((connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT value FROM kv WHERE key = $key";
        command.Parameters.AddWithValue("$key", key);
        return command.ExecuteScalar() as string;
    });

    public void Set(string key, string? value) => database.InTransaction((connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        if (value is null)
        {
            command.CommandText = "DELETE FROM kv WHERE key = $key";
            command.Parameters.AddWithValue("$key", key);
        }
        else
        {
            command.CommandText = "INSERT INTO kv (key, value) VALUES ($key, $value) ON CONFLICT(key) DO UPDATE SET value = $value";
            command.Parameters.AddWithValue("$key", key);
            command.Parameters.AddWithValue("$value", value);
        }
        command.ExecuteNonQuery();
    });

    public long GetLong(string key) => long.TryParse(Get(key), System.Globalization.NumberStyles.Integer,
        System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : 0;

    public long Increment(string key, long by = 1)
    {
        var value = GetLong(key) + by;
        Set(key, value.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return value;
    }

    public bool GetBool(string key) => Get(key) == "1";

    public void SetBool(string key, bool value) => Set(key, value ? "1" : "0");

    public DateTimeOffset? GetTime(string key) => DateTimeOffset.TryParse(Get(key), System.Globalization.CultureInfo.InvariantCulture,
        System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var value) ? value : null;

    public void SetTime(string key, DateTimeOffset? value) =>
        Set(key, value?.UtcDateTime.ToString("O", System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>Removes everything the agent knows about the device (state Revoked).</summary>
    public void Clear(params string[] keys)
    {
        foreach (var key in keys)
        {
            Set(key, null);
        }
    }
}

/// <summary>Keys of <see cref="AgentStateStore"/>.</summary>
public static class StateKeys
{
    public const string DeviceId = "deviceId";
    public const string State = "state";
    public const string BackoffReturn = "backoffReturn";
    public const string BackoffUntil = "backoffUntil";
    public const string BackoffFailures = "backoffFailures";
    public const string BackoffOperation = "backoffOperation";
    public const string Configuration = "configuration";
    public const string ConfigRejected = "configRejected";
    public const string LastCheckInAt = "lastCheckInAt";
    public const string LastScanAt = "lastScanAt";
    public const string LastEnrollAttemptAt = "lastEnrollAttemptAt";
    public const string PendingEnrollment = "pendingEnrollment";
    public const string PendingEnrollmentAt = "pendingEnrollmentAt";
    public const string LastReenrollAt = "lastReenrollAt";
    public const string LastAssignedSequence = "lastAssignedSequence";
    public const string DroppedBatchCount = "droppedBatchCount";
    public const string RejectedBatchCount = "rejectedBatchCount";
    public const string ServiceStarts = "serviceStarts";
    public const string LastCrashAt = "lastCrashAt";
    public const string Running = "running";
    public const string LastAliveAt = "lastAliveAt";
    public const string BlockedVersion = "blockedVersion";
    public const string KeyProtection = "keyProtection";
    public const string LastStateAttemptAt = "lastStateAttemptAt";
}
