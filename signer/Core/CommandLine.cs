using System.Globalization;
using System.Text.Json;

namespace ShadowSweepWindows.KeyGen;

/// <summary>
/// Command-line interface, shared by sswkeygen.exe and ShadowSweepWindows.KeyGen.exe.
///
/// Exit codes: 0 success · 1 key invalid/expired (verify) · 2 bad arguments · 3 signing key problem · 4 other error.
/// With --json, results go to standard output as a single JSON object and errors as {"error": "..."}.
/// </summary>
public static class CommandLine
{
    public const int Ok = 0, Invalid = 1, Usage = 2, KeyProblem = 3, Failure = 4;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public static int Run(string[] args)
    {
        var json = Has(args, "--json");
        try
        {
            if (args.Length == 0)
                return Interactive();

            var command = args[0].ToLowerInvariant();
            return command switch
            {
                "issue" => Issue(args, json),
                "verify" => Verify(args, json),
                "newkeys" => NewKeys(args, json),
                "pubkey" => PubKey(args, json),
                "list" => List(args, json),
                "catalog-sign" => CatalogSign(args, json),
                "catalog-verify" => CatalogVerify(args, json),
                "catalog-validate" => CatalogValidate(args, json),
                "catalog-version" => PrintCatalogVersion(json),
                "help" or "--help" or "-h" or "/?" => Help(),
                _ => UsageError($"Unknown command “{args[0]}”.", json)
            };
        }
        catch (KeyFileException ex)
        {
            return Error(ex.Message, KeyProblem, json);
        }
        catch (ArgumentException ex)
        {
            return Error(ex.Message, Usage, json);
        }
        catch (Exception ex)
        {
            return Error(ex.Message, Failure, json);
        }
    }

    // ================= Commands =================

    private static int Issue(string[] args, bool json)
    {
        var name = Option(args, "--name") ?? "";
        var email = Option(args, "--email") ?? "";
        if (name.Length == 0 && email.Length == 0)
            return UsageError("issue needs --name and/or --email.", json);

        var expires = ParseExpiry(args);
        var keyPath = LicenseKeys.RequirePrivateKey(Option(args, "--key"));
        var license = LicenseKeys.Issue(keyPath, name, email, expires, Option(args, "--id"),
            Option(args, "--tier") ?? "pro", writeLog: !Has(args, "--no-log"));

        if (json)
        {
            WriteJson(new
            {
                key = license.Key,
                licenseId = license.LicenseId,
                name = license.Name,
                email = license.Email,
                tier = license.Tier,
                expires = license.Expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                issuedUtc = license.IssuedAtUtc.ToString("o", CultureInfo.InvariantCulture),
                customerMessage = Has(args, "--message") ? LicenseKeys.CustomerMessage(license) : null
            });
        }
        else if (Has(args, "--message"))
        {
            Console.WriteLine(LicenseKeys.CustomerMessage(license));
        }
        else
        {
            // Just the key, so scripts can capture it directly.
            Console.WriteLine(license.Key);
        }
        return Ok;
    }

    private static int Verify(string[] args, bool json)
    {
        var key = args.Skip(1).FirstOrDefault(a => a.StartsWith(LicenseKeys.Prefix, StringComparison.Ordinal))
                  ?? Option(args, "--license");
        if (string.IsNullOrEmpty(key))
            return UsageError("verify needs a key, e.g. verify SSW1.xxxx.yyyy", json);

        var result = LicenseKeys.Verify(LicenseKeys.RequirePrivateKey(Option(args, "--key")), key);
        if (json)
        {
            WriteJson(new
            {
                valid = result.Valid,
                expired = result.Expired,
                message = result.Message,
                name = result.Name,
                email = result.Email,
                licenseId = result.LicenseId,
                tier = result.Tier,
                expires = result.Expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                issued = result.Issued?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            });
        }
        else
        {
            Console.WriteLine(result.Valid ? "VALID" : "INVALID");
            Console.WriteLine(result.Message);
            if (result.Valid || result.Expired)
            {
                Console.WriteLine($"Licensed to: {result.Name}");
                if (!string.IsNullOrEmpty(result.Email)) Console.WriteLine($"Email:       {result.Email}");
                Console.WriteLine($"License ID:  {result.LicenseId}");
                Console.WriteLine($"Tier:        {result.Tier}");
            }
        }
        return result.Valid ? Ok : Invalid;
    }

    private static int NewKeys(string[] args, bool json)
    {
        var target = Option(args, "--out") ?? LicenseKeys.FindPrivateKey() ?? LicenseKeys.DefaultKeyPath;
        if (File.Exists(target) && !Has(args, "--force"))
            return UsageError($"A signing key already exists at {target}. Keys issued with it stop working once the app uses a new public key. " +
                              "Add --force to replace it (the old key is backed up), or --out <path> to write somewhere else.", json);

        var publicKey = LicenseKeys.CreateKeyPair(target);
        if (json)
        {
            WriteJson(new { privateKeyPath = Path.GetFullPath(target), publicKey });
        }
        else
        {
            Console.WriteLine($"New private key: {Path.GetFullPath(target)}");
            Console.WriteLine("Paste this public key into PublicKeyBase64 in src/ShadowSweepWindows/Services/LicenseService.cs:");
            Console.WriteLine(publicKey);
        }
        return Ok;
    }

    private static int PubKey(string[] args, bool json)
    {
        var keyPath = LicenseKeys.RequirePrivateKey(Option(args, "--key"));
        var publicKey = LicenseKeys.PublicKey(keyPath);
        if (json) WriteJson(new { privateKeyPath = keyPath, publicKey });
        else Console.WriteLine(publicKey);
        return Ok;
    }

    private static int List(string[] args, bool json)
    {
        var keyPath = LicenseKeys.RequirePrivateKey(Option(args, "--key"));
        var items = LicenseKeys.ReadLog(keyPath);
        var search = Option(args, "--search");
        if (!string.IsNullOrWhiteSpace(search))
            items = items.Where(l => l.Name.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                                     l.Email.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                                     l.LicenseId.Contains(search, StringComparison.OrdinalIgnoreCase)).ToList();

        if (json)
        {
            WriteJson(items.Select(l => new
            {
                licenseId = l.LicenseId, name = l.Name, email = l.Email, tier = l.Tier,
                expires = l.Expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                issuedUtc = l.IssuedAtUtc.ToString("o", CultureInfo.InvariantCulture), key = l.Key
            }));
        }
        else
        {
            foreach (var l in items)
                Console.WriteLine($"{l.IssuedAtUtc:yyyy-MM-dd}  {l.LicenseId,-20} {l.Name,-28} {(l.Expires?.ToString("yyyy-MM-dd") ?? "lifetime"),-10}");
            Console.WriteLine($"{items.Count} license(s). Log: {LicenseKeys.LogPath(keyPath)}");
        }
        return Ok;
    }

    private static int CatalogSign(string[] args, bool json)
    {
        var input = Option(args, "--in");
        if (string.IsNullOrEmpty(input))
            return UsageError("catalog-sign needs --in <catalog.json>.", json);
        if (!File.Exists(input))
            return UsageError($"{input} doesn't exist.", json);
        var output = Option(args, "--out") ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(input))!, "catalog.signed.json");
        int? version = null;
        var v = Option(args, "--version");
        if (string.Equals(v, "auto", StringComparison.OrdinalIgnoreCase))
            version = LicenseKeys.AutoCatalogVersion();
        else if (v != null)
        {
            if (!int.TryParse(v, out var n))
                return UsageError("--version must be a whole number or \"auto\".", json);
            version = n;
        }

        var result = LicenseKeys.SignCatalog(LicenseKeys.RequirePrivateKey(Option(args, "--key")), input, output, version,
            Option(args, "--safe-names"));
        if (json)
            WriteJson(new { output = result.OutputPath, version = result.Version, published = result.Published, tools = result.Tools });
        else
            Console.WriteLine($"Signed catalog version {result.Version} ({result.Tools} AI tools) written to {result.OutputPath}\nUpload it to the address in AppInfo.CatalogUrl.");
        return Ok;
    }

    private static int PrintCatalogVersion(bool json)
    {
        var v = LicenseKeys.AutoCatalogVersion();
        if (json) WriteJson(new { version = v });
        else Console.WriteLine(v);
        return Ok;
    }

    private static int CatalogValidate(string[] args, bool json)
    {
        var input = Option(args, "--in") ?? args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
        if (string.IsNullOrEmpty(input) || !File.Exists(input))
            return UsageError("catalog-validate needs --in <catalog.json>.", json);
        var safePath = Option(args, "--safe-names") ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(input))!, "safe-app-names.txt");
        var result = CatalogValidator.Validate(File.ReadAllText(input), CatalogValidator.ReadSafeNames(safePath));

        if (json)
        {
            WriteJson(new { ok = result.Ok, errors = result.Errors, warnings = result.Warnings, tools = result.Tools, apps = result.Apps, engines = result.Engines });
        }
        else
        {
            foreach (var e in result.Errors) Console.WriteLine("ERROR   " + e);
            foreach (var w in result.Warnings) Console.WriteLine("warning " + w);
            Console.WriteLine(result.Ok
                ? $"OK: {result.Tools} AI tools, {result.Apps} apps with built-in AI, {result.Engines} AI engines."
                : $"FAILED: {result.Errors.Count} problem(s) must be fixed before publishing.");
        }
        return result.Ok ? Ok : Invalid;
    }

    private static int CatalogVerify(string[] args, bool json)
    {
        var file = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
        if (string.IsNullOrEmpty(file) || !File.Exists(file))
            return UsageError("catalog-verify needs the path of a signed catalog file.", json);
        var message = LicenseKeys.VerifyCatalog(LicenseKeys.RequirePrivateKey(Option(args, "--key")), file);
        if (json) WriteJson(new { valid = true, message });
        else Console.WriteLine(message);
        return Ok;
    }

    private static int Help()
    {
        Console.WriteLine("""
ShadowSweep license generator

  issue   --name "Jane Doe" [--email jane@example.com] [--id ORDER-1001]
          [--expires 2027-12-31 | --days 365 | --lifetime] [--tier pro]
          [--message] [--json] [--no-log] [--key <private.key>]
          Prints the new key (or a ready-to-send customer message with --message).

  verify  <key> [--json] [--key <private.key>]
  list    [--search text] [--json] [--key <private.key>]
  pubkey  [--key <private.key>]
  newkeys [--out <path>] [--force]

  catalog-validate --in catalog.json [--safe-names safe-app-names.txt] [--json]
                 Checks patterns, ids, risks, entry order and false alarms against common app names.
  catalog-sign   --in catalog.json [--out catalog.signed.json] [--version auto|<n>] [--key <private.key>]
                 Signs a detection catalog exported with: ShadowSweepWindows.exe --export-catalog catalog.json
  catalog-verify <catalog.signed.json> [--key <private.key>]

Signing key lookup: --key, then the SSW_PRIVATE_KEY environment variable, then
tools\ShadowSweepWindows.KeyGen\keys\private.key, then %LOCALAPPDATA%\ShadowSweep KeyGen\private.key.

Exit codes: 0 ok, 1 invalid key, 2 bad arguments, 3 signing key problem, 4 other error.
Every issued key is logged to issued-licenses.csv next to the signing key.
""");
        return Ok;
    }

    private static int Interactive()
    {
        Console.WriteLine("ShadowSweep license generator (type \"help\" for command-line options)");
        Console.WriteLine();
        Console.Write("Customer name: ");
        var name = Console.ReadLine()?.Trim() ?? "";
        Console.Write("Email (optional): ");
        var email = Console.ReadLine()?.Trim() ?? "";
        if (name.Length == 0 && email.Length == 0)
        {
            Console.WriteLine("A name or email is required.");
            return Usage;
        }
        Console.Write("Expires (yyyy-MM-dd, blank for lifetime): ");
        var expiresText = Console.ReadLine()?.Trim();
        DateTime? expires = string.IsNullOrEmpty(expiresText) ? null : ParseDate(expiresText);
        Console.Write("Order / license ID (optional): ");
        var id = Console.ReadLine()?.Trim();

        var license = LicenseKeys.Issue(LicenseKeys.RequirePrivateKey(), name, email, expires, id);
        Console.WriteLine();
        Console.WriteLine(LicenseKeys.CustomerMessage(license));
        return Ok;
    }

    // ================= Helpers =================

    private static DateTime? ParseExpiry(string[] args)
    {
        if (Has(args, "--lifetime"))
            return null;
        var days = Option(args, "--days");
        if (days != null)
        {
            if (!int.TryParse(days, out var n) || n < 1)
                throw new ArgumentException("--days must be a whole number of 1 or more.");
            return DateTime.Today.AddDays(n);
        }
        var expires = Option(args, "--expires");
        return expires == null ? null : ParseDate(expires);
    }

    private static DateTime ParseDate(string text)
        => DateTime.TryParseExact(text, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? d
            : throw new ArgumentException($"“{text}” isn't a date like 2027-12-31.");

    private static string? Option(string[] args, string name)
    {
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        }
        return null;
    }

    private static bool Has(string[] args, string flag)
        => args.Any(a => string.Equals(a, flag, StringComparison.OrdinalIgnoreCase));

    private static void WriteJson(object value) => Console.WriteLine(JsonSerializer.Serialize(value, JsonOptions));

    private static int UsageError(string message, bool json)
    {
        var code = Error(message, Usage, json);
        if (!json)
            Console.Error.WriteLine("Run with \"help\" to see all options.");
        return code;
    }

    private static int Error(string message, int code, bool json)
    {
        if (json)
            WriteJson(new { error = message, exitCode = code });
        else
            Console.Error.WriteLine("Error: " + message);
        return code;
    }
}
