using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Flurl.Http;
using Microsoft.Net.Http.Headers;

namespace ip2wildcard
{
    public class Program
    {
        private const string Version = "0.1";
        // Not a perfect IP address regex but it's good enough
        private const string ExpectedLineFormatRegex = @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$";

        public static class ArgumentKeys
        {
            public const string InputUrl = "input-url";

            public const string OutputFile = "output-file";

            public const string UnixNewlines = "unix-newlines";

            public const string Version = "version";

            public const string Help = "help";
        }

        private static readonly IReadOnlyDictionary<string, (string Description, bool IsRequired, bool IsValueRequired)> argumentKeys = new Dictionary<string, (string Description, bool IsRequired, bool IsValueRequired)>
        {
            { ArgumentKeys.InputUrl, ("A valid HTTP(S) URL to a plaintext input file containing a list of subnets. Each subnet must be on a separate line denoted by: the first usable address followed by a single space (' '), then the last usable address. (e.g. '192.168.0.0 192.168.0.24')", IsRequired: true, IsValueRequired: true) },
            { ArgumentKeys.OutputFile, ("A path to a file to write the output to. If this is omitted, then write to stdout instead.", IsRequired: false, IsValueRequired: true) },
            { ArgumentKeys.UnixNewlines, ("Explicitly use UNIX newlines in the output. If this is not passed, defaults to the newline character(s) appropriate for the current environment.", IsRequired: false, IsValueRequired: false) },
            { ArgumentKeys.Version, ("Show version information.", IsRequired: false, IsValueRequired: false) },
            { ArgumentKeys.Help, ("Show this text.", IsRequired: false, IsValueRequired: false) },
        };

        private static readonly string userAgent = $"ip2wildcard/{Program.Version}";

        public static async Task<int> Main(string[] args)
        {
            var exitCode = 1;
            var arguments = default(IDictionary<string, string?>);
            try
            {
                ////args =
                ////[
                ////    "--input-url",
                ////    @"https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chn_ip.txt"
                ////];

                arguments = Program.GetArgs(args);
                if (arguments.ContainsKey(ArgumentKeys.Version))
                {
                    await Program.ShowVersionAsync();
                    return 0;
                }

                var outputStream = default(Stream?);
                try
                {
                    if (!arguments.TryGetValue(ArgumentKeys.InputUrl, out var inputUrlString) ||
                        !Uri.TryCreate(inputUrlString, UriKind.Absolute, out var inputUrl) ||
                        !new[] { "http", "https" }.Contains(inputUrl.Scheme, StringComparer.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException("A valid absolute HTTP(S) input url is required");
                    }

                    using (var cts = new CancellationTokenSource())
                    {
                        Console.CancelKeyPress += async (o, e) => await cts.CancelAsync();
                        var networkList = Program.GetNetworkListAsync(inputUrl, cts.Token);

                        if (arguments.TryGetValue(ArgumentKeys.OutputFile, out var outputFile))
                        {
                            outputStream = Program.GetOutputFileStream(outputFile!);
                        }
                        else
                        {
                            outputStream = Console.OpenStandardOutput();
                        }

                        var newlineDelimiter = arguments.ContainsKey(ArgumentKeys.UnixNewlines)
                            ? new string((char)10, 1)
                            : Environment.NewLine;

                        await Program.WriteOutAsync(networkList, outputStream, newlineDelimiter, cancellationToken: cts.Token);

                        exitCode = 0;
                    }
                }
                catch (OperationCanceledException)
                {
                    exitCode = 0;
                }
                catch (Exception ex)
                {
                    exitCode = ex.HResult > 0 ? ex.HResult : 1;
                    await Console.Error.WriteLineAsync($"Caught unhandled exception: {ex}");
                }
                finally
                {
                    if (outputStream != null)
                    {
                        await outputStream.DisposeAsync();
                    }
                }
            }
            catch (ArgumentException ex)
            {
                exitCode = 1;
                await Program.ShowHelpAsync(ex);
            }

            return exitCode;
        }

        private static async Task ShowIntroAsync(string? message = default(string?), CancellationToken cancellationToken = default(CancellationToken))
        {
            await Console.Out.WriteLineAsync($"{AppDomain.CurrentDomain.FriendlyName}: a small command-line application for generating wildcard IPv4 subnets for dnscrypt-proxy.{Environment.NewLine}".ToCharArray(), cancellationToken);
            if (!string.IsNullOrEmpty(message))
            {
                await Console.Out.WriteLineAsync(message.ToCharArray(), cancellationToken);
            }
        }

        private static Task ShowVersionAsync(CancellationToken cancellationToken = default(CancellationToken))
        {
            return Console.Out.WriteLineAsync($"{AppDomain.CurrentDomain.FriendlyName} v{Program.Version}".ToCharArray(), cancellationToken);
        }

        private static async Task ShowHelpAsync(Exception? exception = default(Exception?), CancellationToken cancellationToken = default(CancellationToken))
        {
            const string tab = "    ";

            var cliBuilder = new StringBuilder();
            if (exception != null)
            {
                cliBuilder.AppendLine(exception.Message);
            }
            else
            {
                await Program.ShowIntroAsync(cancellationToken: cancellationToken);
            }

            cliBuilder.Append($"Usage: {AppDomain.CurrentDomain.FriendlyName}");
            foreach (var kvp in Program.argumentKeys)
            {
                cliBuilder.Append(' ');

                if (!kvp.Value.IsRequired)
                {
                    cliBuilder.Append('[');
                }

                cliBuilder.Append($"--{kvp.Key}");
                if (kvp.Value.IsValueRequired)
                {
                    cliBuilder.Append(string.Concat(" {", kvp.Key, "}"));
                }

                if (!kvp.Value.IsRequired)
                {
                    cliBuilder.Append(']');
                }
            }

            cliBuilder.AppendLine("Command-line arguments:");
            var maxLengthCol1 = Program.argumentKeys.Select(x => (x.Key.Length + 2) + (x.Value.IsValueRequired ? x.Key.Length + 2 : 0)).Max() + (tab.Length * 3);
            cliBuilder.AppendLine();
            foreach (var kvp in Program.argumentKeys)
            {
                var thisArgString = new StringBuilder(string.Concat(tab, "--", kvp.Key));
                if (kvp.Value.IsValueRequired)
                {
                    thisArgString = thisArgString.Append(string.Concat(" {", kvp.Key, "}"));
                }

                maxLengthCol1 = Math.Max(maxLengthCol1, thisArgString.Length);

                while (thisArgString.Length < maxLengthCol1)
                {
                    thisArgString.Append(' ');
                }

                thisArgString.Append($"{(!kvp.Value.IsRequired ? "Optional." : "Required.")} ");
                thisArgString.Append(kvp.Value.Description);
                cliBuilder.AppendLine(thisArgString.ToString());
            }

            await Console.Out.WriteLineAsync(cliBuilder, cancellationToken);
        }

        private static Stream GetOutputFileStream(string outputFilePath)
        {
            if (string.IsNullOrWhiteSpace(outputFilePath))
            {
                throw new ArgumentException("Must a valid file path", nameof(outputFilePath));
            }

            if (Directory.Exists(outputFilePath))
            {
                throw new ArgumentException($"Cannot write to file at '{outputFilePath}' as a directory already exists at this path");
            }

            return File.OpenWrite(outputFilePath);
        }

        private static async Task WriteOutAsync(IAsyncEnumerable<IPNetwork2> items, Stream outputStream, string delimiter, string encodingName = "utf-8", CancellationToken cancellationToken = default(CancellationToken))
        {
            var encoding = Encoding.GetEncoding(encodingName);
            var replacementRegex = new Regex(@"\.\d{1,3}\/24$", RegexOptions.Compiled);
            var lineIndex = 0;
            using (var streamWriter = new StreamWriter(outputStream, encoding))
            {
                await foreach (var item in items)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }

                    // TODO: We could make this more efficient by using larger CIDRs and doing replacement on octets 3 and 2 as well, but that's a bit more of a faff that I don't have time to implement right now.
                    foreach (var childSubnet in item.Subnet(24))
                    {
                        if (cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        var thisValue = new StringBuilder();
                        if (lineIndex > 0)
                        {
                            thisValue.Append(delimiter);
                        }

                        thisValue.Append(replacementRegex.Replace(childSubnet.ToString(), ".*"));
                        await streamWriter.WriteAsync(thisValue, cancellationToken);

                        lineIndex++;
                    }
                }
            }
        }

        private static async IAsyncEnumerable<IPNetwork2> GetNetworkListAsync(Uri inputUrl, [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            using (var client = new FlurlClient(inputUrl.ToString()))
            {
                var request = client.Request()
                    .WithHeader(HeaderNames.UserAgent, Program.userAgent);

                var regex = new Regex(Program.ExpectedLineFormatRegex, RegexOptions.Compiled);
                using (var responseStream = await request.GetStreamAsync(HttpCompletionOption.ResponseHeadersRead, cancellationToken))
                using (var streamReader = new StreamReader(responseStream, Encoding.UTF8, true))
                {
                    var lineIndex = 0;
                    while (!cancellationToken.IsCancellationRequested &&
                        !streamReader.EndOfStream)
                    {
                        var line = default(string?);
                        var result = default(IPNetwork2?);
                        try
                        {
                            line = await streamReader.ReadLineAsync(cancellationToken);
                            if (!string.IsNullOrWhiteSpace(line) &&
                                regex.IsMatch(line))
                            {
                                var addresses = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                                if (addresses.Length == 2)
                                {
                                    result = IPNetwork2.WideSubnet(addresses[0], addresses[1]);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"WARNING: Couldn't parse line number {lineIndex} with value '{line}' -- error message was '{ex.Message}'");
                        }

                        if (result != null)
                        {
                            yield return result!;
                        }

                        lineIndex++;
                    }
                }
            }
        }

        private static IDictionary<string, string?> GetArgs(string[] args)
        {
            var argsList = args.ToList();
            var results = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            var processedIndexes = new List<int>();

            if (args.Any(x => string.Equals(x.TrimStart('-'), ArgumentKeys.Version, StringComparison.OrdinalIgnoreCase)))
            {
                results.Add("version", default(string?));
                return results;
            }

            foreach (var argumentKvp in Program.argumentKeys)
            {
                var passedArgument = argsList.Where(x => string.Equals(x.TrimStart('-'), argumentKvp.Key, StringComparison.OrdinalIgnoreCase))
                    .LastOrDefault();
                if (!string.IsNullOrEmpty(passedArgument))
                {
                    var argumentIndex = argsList.LastIndexOf(passedArgument);
                    processedIndexes.Add(argumentIndex);

                    var resultingKey = argumentKvp.Key;
                    var resultingValue = default(string?);

                    if (argumentKvp.Value.IsValueRequired)
                    {
                        resultingValue = argsList.ElementAtOrDefault(argumentIndex + 1);
                        processedIndexes.Add(argumentIndex + 1);

                        if (string.IsNullOrWhiteSpace(resultingValue))
                        {
                            throw new ArgumentException($"Expected a value for argument '{argumentKvp.Key.TrimStart('-')}', but none could be found");
                        }
                    }

                    results.Add(resultingKey, resultingValue);
                }
                else if (argumentKvp.Value.IsRequired)
                {
                    throw new ArgumentException($"Argument '{argumentKvp.Key}' is required");
                }
            }

            for (var i = 0; i < argsList.Count; i++)
            {
                if (!processedIndexes.Contains(i))
                {
                    Console.Write($"Unrecognised argument: {argsList[i]}");
                }
            }

            return results;
        }
    }
}
