using System.Text.Json;
using System.Text.RegularExpressions;

namespace ShadowSweepWindows.KeyGen;

/// <summary>
/// Checks a detection catalog before it is signed, using the same .NET regular-expression engine and options
/// as ShadowSweep itself, so anything that passes here behaves the same way on customers' PCs.
/// </summary>
public static class CatalogValidator
{
    private static readonly string[] Risks = { "Info", "Low", "Medium", "High", "Critical" };
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);
    private static readonly Regex DomainPattern = new(@"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$", RegexOptions.Compiled);

    public sealed record Result(List<string> Errors, List<string> Warnings, int Tools, int Apps, int Engines)
    {
        public bool Ok => Errors.Count == 0;
    }

    private sealed record Sig(string Id, string Name, Regex Pattern, Regex? Exclude, List<string> Examples)
    {
        public bool Matches(string text)
        {
            try
            {
                return Pattern.IsMatch(text) && (Exclude == null || !Exclude.IsMatch(text));
            }
            catch (RegexMatchTimeoutException)
            {
                return false;
            }
        }
    }

    public static Result Validate(string catalogJson, IEnumerable<string>? safeNames = null)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(catalogJson, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        }
        catch (JsonException ex)
        {
            errors.Add($"catalog.json isn't valid JSON (line {ex.LineNumber + 1}): {ex.Message}");
            return new Result(errors, warnings, 0, 0, 0);
        }

        using (doc)
        {
            var root = doc.RootElement;
            var sigs = new List<Sig>();

            // ---- AI tools ----
            if (!root.TryGetProperty("signatures", out var signatures) || signatures.ValueKind != JsonValueKind.Array || signatures.GetArrayLength() == 0)
            {
                errors.Add("\"signatures\" is missing or empty.");
            }
            else
            {
                var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var index = 0;
                foreach (var s in signatures.EnumerateArray())
                {
                    index++;
                    var id = Str(s, "id");
                    var where = string.IsNullOrEmpty(id) ? $"AI tool #{index}" : $"AI tool \"{id}\"";
                    if (string.IsNullOrWhiteSpace(id)) errors.Add($"{where} has no \"id\".");
                    else if (!ids.Add(id)) errors.Add($"{where}: the id is used more than once.");
                    var name = Str(s, "name");
                    if (string.IsNullOrWhiteSpace(name)) errors.Add($"{where} has no \"name\".");
                    CheckRisk(s, "risk", where, errors);
                    if (string.IsNullOrWhiteSpace(Str(s, "dataExposure"))) warnings.Add($"{where} has no \"dataExposure\" text.");

                    var pattern = Compile(Str(s, "pattern"), $"{where} pattern", errors, required: true);
                    var exclude = Compile(Str(s, "exclude"), $"{where} exclude", errors, required: false);

                    if (s.TryGetProperty("domains", out var domains) && domains.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var d in domains.EnumerateArray())
                        {
                            var domain = d.GetString()?.Trim().ToLowerInvariant() ?? "";
                            if (!DomainPattern.IsMatch(domain))
                                errors.Add($"{where}: \"{domain}\" isn't a valid domain (use names like example.com, without https://).");
                        }
                    }

                    var examples = new List<string>();
                    if (s.TryGetProperty("examples", out var ex) && ex.ValueKind == JsonValueKind.Array)
                        examples.AddRange(ex.EnumerateArray().Select(e => e.GetString() ?? "").Where(e => e.Length > 0));

                    if (pattern != null && !string.IsNullOrWhiteSpace(id))
                        sigs.Add(new Sig(id, name, pattern, exclude, examples));
                }
            }

            // Pattern behaviour checks (the kind of mistake that reaches customers).
            foreach (var sig in sigs)
            {
                foreach (var example in sig.Examples)
                {
                    if (!sig.Matches(example))
                        errors.Add($"AI tool \"{sig.Id}\": its pattern doesn't match its own example \"{example}\".");
                }

                foreach (var probe in new[] { sig.Name }.Concat(sig.Examples).Where(p => p.Length > 0))
                {
                    var first = sigs.FirstOrDefault(other => other.Matches(probe));
                    if (first == null)
                    {
                        if (probe == sig.Name && sig.Examples.Count == 0)
                            warnings.Add($"AI tool \"{sig.Id}\": its pattern doesn't match its own name \"{sig.Name}\". Add an \"examples\" list so it can be tested.");
                    }
                    else if (first.Id != sig.Id)
                    {
                        errors.Add($"AI tool \"{sig.Id}\": \"{probe}\" would be reported as \"{first.Id}\" because that entry comes first. Move \"{sig.Id}\" above \"{first.Id}\".");
                    }
                }
            }

            var safe = (safeNames ?? Enumerable.Empty<string>()).ToList();
            foreach (var name in safe)
            {
                var hit = sigs.FirstOrDefault(s => s.Matches(name));
                if (hit != null)
                    errors.Add($"False alarm: \"{name}\" isn't an AI tool, but the pattern for \"{hit.Id}\" matches it. Make that pattern more specific or add an \"exclude\".");
            }

            // ---- Apps with built-in AI ----
            var apps = 0;
            if (root.TryGetProperty("embeddedApps", out var embedded) && embedded.ValueKind == JsonValueKind.Array)
            {
                var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var a in embedded.EnumerateArray())
                {
                    apps++;
                    var id = Str(a, "id");
                    var where = string.IsNullOrEmpty(id) ? $"App #{apps}" : $"App \"{id}\"";
                    if (string.IsNullOrWhiteSpace(id)) errors.Add($"{where} has no \"id\".");
                    else if (!ids.Add(id)) errors.Add($"{where}: the id is used more than once.");
                    if (string.IsNullOrWhiteSpace(Str(a, "appName"))) errors.Add($"{where} has no \"appName\".");
                    if (string.IsNullOrWhiteSpace(Str(a, "feature"))) errors.Add($"{where} has no \"feature\".");
                    CheckRisk(a, "risk", where, errors);
                    Compile(Str(a, "pattern"), $"{where} pattern", errors, required: true);
                    Compile(Str(a, "exclude"), $"{where} exclude", errors, required: false);
                }
            }

            // ---- AI engine files ----
            var engines = 0;
            if (root.TryGetProperty("engineFiles", out var engineFiles) && engineFiles.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in engineFiles.EnumerateArray())
                {
                    engines++;
                    var where = $"Engine \"{Str(e, "component")}\"";
                    if (string.IsNullOrWhiteSpace(Str(e, "component"))) errors.Add($"Engine #{engines} has no \"component\".");
                    if (!e.TryGetProperty("weight", out var w) || !w.TryGetInt32(out var weight) || weight < 1 || weight > 3)
                        errors.Add($"{where}: \"weight\" must be 1, 2 or 3.");
                    var rx = Compile(Str(e, "pattern"), $"{where} pattern", errors, required: true);
                    // Engine patterns must look for specific files, not match every DLL.
                    if (rx != null && (rx.IsMatch("kernel32.dll") || rx.IsMatch("msvcp140.dll") || rx.IsMatch("setup.exe")))
                        errors.Add($"{where}: the pattern matches ordinary Windows files. Make it more specific.");
                }
            }

            return new Result(errors, warnings, sigs.Count, apps, engines);
        }
    }

    public static List<string> ReadSafeNames(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
            return new List<string>();
        return File.ReadAllLines(path)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith('#'))
            .ToList();
    }

    private static Regex? Compile(string pattern, string what, List<string> errors, bool required)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            if (required) errors.Add($"{what} is empty.");
            return null;
        }
        try
        {
            var rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, Timeout);
            // A pattern that matches nearly everything is almost certainly a mistake.
            if (rx.IsMatch("") || rx.IsMatch("a") || rx.IsMatch("Setup"))
                errors.Add($"{what} matches almost anything (\"{pattern}\"). Make it more specific.");
            return rx;
        }
        catch (ArgumentException ex)
        {
            errors.Add($"{what} isn't a valid pattern: {ex.Message}");
            return null;
        }
        catch (RegexMatchTimeoutException)
        {
            errors.Add($"{what} is too slow to match safely. Simplify it.");
            return null;
        }
    }

    private static void CheckRisk(JsonElement e, string property, string where, List<string> errors)
    {
        var risk = Str(e, property);
        if (!Risks.Contains(risk, StringComparer.OrdinalIgnoreCase))
            errors.Add($"{where}: \"risk\" must be one of {string.Join(", ", Risks)} (found \"{risk}\").");
    }

    private static string Str(JsonElement e, string property)
        => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(property, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? ""
            : "";
}
