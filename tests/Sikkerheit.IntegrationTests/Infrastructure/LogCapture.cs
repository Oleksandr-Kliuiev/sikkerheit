using Microsoft.Extensions.Logging;

namespace Sikkerheit.IntegrationTests.Infrastructure;

public sealed record LogEntry(LogLevel Level, string Category, string Message);

/// <summary>Collects the log records of a service instance: in Azure an Error record raises the log alert (06).</summary>
public sealed class LogCapture : ILoggerProvider
{
    private readonly List<LogEntry> _entries = [];

    public IReadOnlyList<LogEntry> Entries
    {
        get
        {
            lock (_entries)
            {
                return [.. _entries];
            }
        }
    }

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);

    public void Dispose()
    {
    }

    private sealed class Logger(LogCapture capture, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }
            lock (capture._entries)
            {
                capture._entries.Add(new LogEntry(logLevel, category, formatter(state, exception)));
            }
        }
    }
}
