using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DeviceTrust.Cli.Harness
{
    /// <summary>Raised by a check that cannot run under the server's current configuration.</summary>
    public sealed class SkipCheckException : Exception
    {
        /// <summary>Creates a skip with the reason to print.</summary>
        public SkipCheckException(string reason)
            : base(reason)
        {
        }
    }

    /// <summary>Raised when an assertion inside a check fails.</summary>
    public sealed class CheckFailedException : Exception
    {
        /// <summary>Creates a failure with the detail to print.</summary>
        public CheckFailedException(string detail)
            : base(detail)
        {
        }
    }

    /// <summary>
    /// Runs a list of named checks and prints them in the same shape as the
    /// Python conformance suite, so the two outputs can be read side by side.
    /// </summary>
    /// <remarks>
    /// Checks run in order and share a context, exactly as the Python suite's do.
    /// That is deliberate: enrolling, opening an account and rotating a refresh
    /// token are a sequence, and re-establishing all of it per check would make
    /// a run slow enough that nobody would run it.
    /// </remarks>
    public sealed class CheckRunner
    {
        private readonly List<(string Name, Func<CancellationToken, Task> Body)> _checks =
            new List<(string, Func<CancellationToken, Task>)>();

        /// <summary>How many checks passed.</summary>
        public int Passed { get; private set; }

        /// <summary>How many checks failed.</summary>
        public int Failed { get; private set; }

        /// <summary>How many checks were skipped.</summary>
        public int Skipped { get; private set; }

        /// <summary>Asserts a condition, failing the current check when it does not hold.</summary>
        public static void Expect(bool condition, string detail)
        {
            if (!condition)
            {
                throw new CheckFailedException(detail);
            }
        }

        /// <summary>Adds a check.</summary>
        public CheckRunner Add(string name, Func<CancellationToken, Task> body)
        {
            _checks.Add((name, body));
            return this;
        }

        /// <summary>Runs every check in order and returns a process exit code.</summary>
        public async Task<int> RunAsync(CancellationToken cancellationToken)
        {
            foreach (var check in _checks)
            {
                try
                {
                    await check.Body(cancellationToken).ConfigureAwait(false);
                }
                catch (SkipCheckException skip)
                {
                    Skipped++;
                    Report.Outcome("SKIP", check.Name + "  (" + skip.Message + ")");
                    continue;
                }
                catch (Exception error)
                {
                    Failed++;
                    Report.Outcome("FAIL", check.Name, error.ToString());
                    continue;
                }

                Passed++;
                Report.Outcome("PASS", check.Name);
            }

            Report.Tally(Passed, Failed, Skipped);
            return Failed == 0 ? 0 : 1;
        }
    }
}
