using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ShadowSweepWindows.KeyGen;

public sealed record IssuedLicense(
    string Key, string Name, string Email, string LicenseId, string Tier, DateTime? Expires, DateTime IssuedAtUtc);

public sealed record VerifyResult(
    bool Valid, bool Expired, string Message, string Name, string Email, string LicenseId, string Tier,
    DateTime? Expires, DateTime? Issued);

/// <summary>
/// Creates and checks ShadowSweep license keys. Shared by the Windows app and the command-line tool.
/// Key format: SSW1.&lt;base64url payload JSON&gt;.&lt;base64url ECDSA P-256 / SHA-256 DER signature&gt;
/// Payload fields: n = name, m = email, t = tier, e = expiry (yyyy-MM-dd or empty), i = license ID, d = issue date.
/// </summary>
public static class LicenseKeys
{
    public const string Prefix = "SSW1.";
    public const string KeyPathEnvironmentVariable = "SSW_PRIVATE_KEY";
    public const string LogFileName = "issued-licenses.csv";

    public static string AppDataDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ShadowSweep KeyGen");

    /// <summary>Where a new key pair goes when no existing key file is found.</summary>
    public static string DefaultKeyPath => Path.Combine(AppDataDir, "private.key");

    // ================= Finding the private key =================

    /// <summary>
    /// Finds the signing key: an explicit path, then the SSW_PRIVATE_KEY environment variable,
    /// then the solution's tools\ShadowSweepWindows.KeyGen\keys folder, then the app data folder.
    /// Returns null when none exists.
    /// </summary>
    public static string? FindPrivateKey(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
            return File.Exists(explicitPath) ? Path.GetFullPath(explicitPath) : null;

        var fromEnv = Environment.GetEnvironmentVariable(KeyPathEnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
            return Path.GetFullPath(fromEnv);

        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var dir = new DirectoryInfo(start);
            for (var i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
            {
                foreach (var candidate in new[]
                         {
                             Path.Combine(dir.FullName, "keys", "private.key"),
                             Path.Combine(dir.FullName, "ShadowSweepWindows.KeyGen", "keys", "private.key"),
                             Path.Combine(dir.FullName, "tools", "ShadowSweepWindows.KeyGen", "keys", "private.key")
                         })
                {
                    if (File.Exists(candidate))
                        return Path.GetFullPath(candidate);
                }
            }
        }

        return File.Exists(DefaultKeyPath) ? DefaultKeyPath : null;
    }

    public static string RequirePrivateKey(string? explicitPath = null)
        => FindPrivateKey(explicitPath) ?? throw new KeyFileException(
            explicitPath != null
                ? $"Signing key not found at {explicitPath}."
                : "No signing key found. Create one with \"newkeys\" or point to it with --key or the SSW_PRIVATE_KEY environment variable.");

    private static ECDsa LoadPrivateKey(string keyPath)
    {
        try
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(File.ReadAllText(keyPath).Trim()), out _);
            return ecdsa;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException)
        {
            throw new KeyFileException($"{keyPath} isn't a valid ShadowSweep signing key.");
        }
    }

    /// <summary>The public key to paste into PublicKeyBase64 in the app's LicenseService.cs.</summary>
    public static string PublicKey(string keyPath)
    {
        using var ecdsa = LoadPrivateKey(keyPath);
        return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    }

    /// <summary>Creates a new key pair. An existing file is backed up first. Returns the new public key.</summary>
    public static string CreateKeyPair(string path)
    {
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        if (File.Exists(full))
            File.Copy(full, $"{full}.{DateTime.Now:yyyyMMdd-HHmmss}.bak");

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(full, Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey()));
        return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    }

    // ================= Issue and verify =================

    public static IssuedLicense Issue(string keyPath, string name, string? email, DateTime? expires,
        string? licenseId, string tier = "pro", bool writeLog = true)
    {
        name = (name ?? "").Trim();
        email = (email ?? "").Trim();
        if (name.Length == 0 && email.Length == 0)
            throw new ArgumentException("Enter the customer's name or email address.");
        if (expires.HasValue && expires.Value.Date < DateTime.Today)
            throw new ArgumentException("The expiry date is in the past.");

        var id = string.IsNullOrWhiteSpace(licenseId) ? NewLicenseId() : licenseId.Trim();
        var issued = DateTime.UtcNow;
        var payload = new Dictionary<string, string>
        {
            ["n"] = name.Length > 0 ? name : email,
            ["m"] = email,
            ["t"] = string.IsNullOrWhiteSpace(tier) ? "pro" : tier.Trim().ToLowerInvariant(),
            ["e"] = expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "",
            ["i"] = id,
            ["d"] = issued.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
        };
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));

        using var ecdsa = LoadPrivateKey(keyPath);
        var signature = ecdsa.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var key = Prefix + ToBase64Url(bytes) + "." + ToBase64Url(signature);

        var license = new IssuedLicense(key, payload["n"], email, id, payload["t"], expires?.Date, issued);
        if (writeLog)
            AppendLog(keyPath, license);
        return license;
    }

    public static VerifyResult Verify(string keyPath, string rawKey)
    {
        var key = new string((rawKey ?? "").Where(c => !char.IsWhiteSpace(c)).ToArray());
        VerifyResult Bad(string message) => new(false, false, message, "", "", "", "", null, null);

        if (key.Length == 0)
            return Bad("Paste a license key to check.");
        if (!key.StartsWith(Prefix, StringComparison.Ordinal))
            return Bad("Not a ShadowSweep key. Keys start with “SSW1.”");
        var parts = key[Prefix.Length..].Split('.');
        if (parts.Length != 2)
            return Bad("The key is incomplete.");

        byte[] payload, signature;
        try
        {
            payload = FromBase64Url(parts[0]);
            signature = FromBase64Url(parts[1]);
        }
        catch (FormatException)
        {
            return Bad("The key is damaged.");
        }

        using (var ecdsa = LoadPrivateKey(keyPath))
        {
            if (!ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
                return Bad("Invalid signature. This key wasn't made with this signing key, or it was altered.");
        }

        try
        {
            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;
            string S(string p) => root.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
            DateTime? D(string p) => DateTime.TryParseExact(S(p), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

            var expires = D("e");
            var expired = expires.HasValue && DateTime.Today > expires.Value;
            var message = expired
                ? $"Valid signature, but it expired on {expires!.Value:MMMM d, yyyy}."
                : expires.HasValue ? $"Valid until {expires.Value:MMMM d, yyyy}." : "Valid lifetime license.";
            return new VerifyResult(!expired, expired, message, S("n"), S("m"), S("i"),
                string.IsNullOrEmpty(S("t")) ? "pro" : S("t"), expires, D("d"));
        }
        catch (JsonException)
        {
            return Bad("The key's contents are damaged.");
        }
    }

    public static string NewLicenseId()
    {
        const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var chars = new char[6];
        for (var i = 0; i < chars.Length; i++)
            chars[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        return $"SSW-{DateTime.UtcNow:yyMMdd}-{new string(chars)}";
    }

    /// <summary>A ready-to-send message for the customer.</summary>
    public static string CustomerMessage(IssuedLicense l)
    {
        var greeting = string.IsNullOrWhiteSpace(l.Name) || l.Name.Contains('@') ? "Hi," : $"Hi {l.Name.Split(' ')[0]},";
        var term = l.Expires.HasValue ? $"It's valid until {l.Expires.Value:MMMM d, yyyy}." : "It never expires.";
        return $"""
{greeting}

Thank you for buying ShadowSweep Pro! Here is your license key:

{l.Key}

To activate it:
1. Open ShadowSweep.
2. Click "Settings & license" in the left sidebar.
3. Paste the key into the License key box and click Activate.

{term} Your license ID is {l.LicenseId}. Keep this email for your records.

If you have any trouble, just reply to this message.

The ShadowSweep team
""";
    }

    // ================= Detection catalog signing =================

    public sealed record CatalogSignResult(string OutputPath, int Version, string Published, int Tools);

    /// <summary>
    /// Signs a detection catalog JSON file (exported with "ShadowSweepWindows.exe --export-catalog") for upload.
    /// Optionally sets its version; the published date is set to today.
    /// </summary>
    /// <summary>A version number that always increases: minutes since 1 January 1970 (UTC).</summary>
    public static int AutoCatalogVersion() => (int)(DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60);

    public static CatalogSignResult SignCatalog(string keyPath, string inputPath, string outputPath, int? version = null,
        string? safeNamesPath = null)
    {
        var check = CatalogValidator.Validate(File.ReadAllText(inputPath),
            CatalogValidator.ReadSafeNames(safeNamesPath ?? Path.Combine(Path.GetDirectoryName(Path.GetFullPath(inputPath))!, "safe-app-names.txt")));
        if (!check.Ok)
            throw new ArgumentException("The catalog wasn't signed because it has problems:\n- " + string.Join("\n- ", check.Errors));

        System.Text.Json.Nodes.JsonNode? node;
        try
        {
            node = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(inputPath),
                documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        }
        catch (JsonException ex)
        {
            throw new ArgumentException($"{Path.GetFileName(inputPath)} isn't valid JSON: {ex.Message}");
        }
        if (node is not System.Text.Json.Nodes.JsonObject obj)
            throw new ArgumentException("The catalog must be a JSON object.");

        if (version.HasValue)
            obj["version"] = version.Value;
        var finalVersion = obj["version"]?.GetValue<int>() ?? throw new ArgumentException("The catalog needs a \"version\" number.");
        if (finalVersion < 2)
            throw new ArgumentException("Use a version of 2 or higher; the app's built-in catalog is version 1.");
        var published = DateTime.Today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        obj["published"] = published;
        var tools = (obj["signatures"] as System.Text.Json.Nodes.JsonArray)?.Count ?? 0;
        if (tools == 0)
            throw new ArgumentException("The catalog has no \"signatures\" (AI tools).");

        var payload = Encoding.UTF8.GetBytes(obj.ToJsonString(new JsonSerializerOptions { WriteIndented = false }));
        using var ecdsa = LoadPrivateKey(keyPath);
        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        var envelope = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            ["format"] = "ssw-catalog-1",
            ["payload"] = Convert.ToBase64String(payload),
            ["signature"] = Convert.ToBase64String(signature)
        }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(outputPath, envelope, new UTF8Encoding(false));
        return new CatalogSignResult(Path.GetFullPath(outputPath), finalVersion, published, tools);
    }

    /// <summary>Checks a signed catalog file. Returns a description, or throws if it's invalid.</summary>
    public static string VerifyCatalog(string keyPath, string signedPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(signedPath));
        var root = doc.RootElement;
        if (!root.TryGetProperty("payload", out var p) || !root.TryGetProperty("signature", out var sig))
            throw new ArgumentException("Not a signed ShadowSweep catalog.");
        var payload = Convert.FromBase64String(p.GetString() ?? "");
        using var ecdsa = LoadPrivateKey(keyPath);
        if (!ecdsa.VerifyData(payload, Convert.FromBase64String(sig.GetString() ?? ""), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            throw new ArgumentException("Invalid signature.");
        using var inner = JsonDocument.Parse(payload);
        var v = inner.RootElement.TryGetProperty("version", out var ve) ? ve.GetInt32() : 0;
        var pub = inner.RootElement.TryGetProperty("published", out var pe) ? pe.GetString() : "";
        var n = inner.RootElement.TryGetProperty("signatures", out var se) ? se.GetArrayLength() : 0;
        return $"Valid catalog: version {v}, published {pub}, {n} AI tools.";
    }

    // ================= Issue log =================

    /// <summary>Every key issued is recorded next to the signing key, so you can look it up or resend it.</summary>
    public static string LogPath(string keyPath) => Path.Combine(Path.GetDirectoryName(Path.GetFullPath(keyPath))!, LogFileName);

    public static void AppendLog(string keyPath, IssuedLicense l)
    {
        var path = LogPath(keyPath);
        var line = string.Join(",", new[]
        {
            l.IssuedAtUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            l.LicenseId, l.Name, l.Email, l.Tier,
            l.Expires?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "",
            l.Key
        }.Select(Csv)) + Environment.NewLine;

        // Several purchases can arrive at once from a payment webhook; retry if the file is busy.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                var isNew = !File.Exists(path);
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                if (isNew)
                    writer.Write("IssuedUtc,LicenseId,Name,Email,Tier,Expires,Key" + Environment.NewLine);
                writer.Write(line);
                return;
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(100);
            }
        }
    }

    public static List<IssuedLicense> ReadLog(string keyPath)
    {
        var list = new List<IssuedLicense>();
        var path = LogPath(keyPath);
        if (!File.Exists(path))
            return list;

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        reader.ReadLine(); // header
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            var f = ParseCsvLine(line);
            if (f.Count < 7)
                continue;
            DateTime.TryParse(f[0], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var issued);
            DateTime? expires = DateTime.TryParseExact(f[5], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var e) ? e : null;
            list.Add(new IssuedLicense(f[6], f[2], f[3], f[1], f[4], expires, issued));
        }
        list.Reverse();
        return list;
    }

    // ================= Helpers =================

    public static string ToBase64Url(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            case 1: throw new FormatException("Invalid base64url length.");
        }
        return Convert.FromBase64String(s);
    }

    private static string Csv(string? s)
    {
        s ??= "";
        return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else if (c == '"') quoted = false;
                else sb.Append(c);
            }
            else if (c == '"') quoted = true;
            else if (c == ',') { fields.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        fields.Add(sb.ToString());
        return fields;
    }
}

/// <summary>The signing key file is missing or unreadable.</summary>
public sealed class KeyFileException : Exception
{
    public KeyFileException(string message) : base(message) { }
}
