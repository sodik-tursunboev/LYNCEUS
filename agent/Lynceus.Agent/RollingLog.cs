using System.Text;
using Microsoft.Extensions.Logging;

namespace Lynceus.Agent;

/// <summary>An append-only text log that starts a new file (keeping one old one) when it passes a size.</summary>
public sealed class RollingLog(string path, long maxBytes = 1024 * 1024)
{
    private readonly object gate = new();

    public void WriteLine(string line)
    {
        lock (gate)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                if (File.Exists(path) && new FileInfo(path).Length > maxBytes)
                {
                    File.Move(path, path + ".1", overwrite: true);
                }

                File.AppendAllText(path, line + "\n", new UTF8Encoding(false));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                // logging must never take the agent down
            }
        }
    }
}

/// <summary>Writes the agent's log lines to a rolling file. Messages already contain hosts and ids only, never URLs.</summary>
public sealed class FileLoggerProvider(RollingLog log) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new FileLogger(log, categoryName);

    public void Dispose()
    {
    }

    private sealed class FileLogger(RollingLog log, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }

            var name = category[(category.LastIndexOf('.') + 1)..];
            log.WriteLine($"{DateTimeOffset.UtcNow:yyyy-MM-dd'T'HH:mm:ss'Z'} {logLevel,-11} {name}: {formatter(state, null)}{(exception is null ? string.Empty : " [" + exception.GetType().Name + "]")}");
        }
    }
}
