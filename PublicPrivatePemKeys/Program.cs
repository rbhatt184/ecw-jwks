using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

class Program
{
    static void Main(string[] args)
    {
        // ------- Config -------
        const int RsaKeySize = 2048;

        // Optional: allow a custom output directory via args[0]
        string outDir = args.Length > 0 ? args[0] : Directory.GetCurrentDirectory();
        Directory.CreateDirectory(outDir);

        string privatePemPath = Path.Combine(outDir, "private_key.pem");
        string publicPemPath = Path.Combine(outDir, "public_key.pem");
        string jwksPath = Path.Combine(outDir, "jwks.json");

        // 1) Generate RSA keypair
        using var rsa = RSA.Create(RsaKeySize);

        // 2) Export PRIVATE KEY (PKCS#8) to PEM
        byte[] pkcs8Private = rsa.ExportPkcs8PrivateKey();
        string privatePem = PemEncode("PRIVATE KEY", pkcs8Private);
        File.WriteAllText(privatePemPath, privatePem, new UTF8Encoding(false));

        // 3) Export PUBLIC KEY (SubjectPublicKeyInfo) to PEM
        byte[] spkiPublic = rsa.ExportSubjectPublicKeyInfo();
        string publicPem = PemEncode("PUBLIC KEY", spkiPublic);
        File.WriteAllText(publicPemPath, publicPem, new UTF8Encoding(false));

        // 4) Build JWKS: extract n/e, compute kid
        var rsaParams = rsa.ExportParameters(false); // public only
        string n = ToBase64Url(rsaParams.Modulus!);
        string e = ToBase64Url(rsaParams.Exponent!); // should be "AQAB"

        // kid = SHA-256 of SPKI DER, hex lowercase
        string kid = Sha256Hex(spkiPublic);

        var jwk = new Jwk
        {
            Kty = "RSA",
            Alg = "RS384",    // eCW requires RS384 for private_key_jwt
            N = n,
            E = e,
            Use = "sig",
            Kid = kid,
            KeyOps = new[] { "verify" }, // optional but included to match your meeting sample
            Ext = true                 // optional but included to match your meeting sample
        };

        var jwks = new Jwks { Keys = new[] { jwk } };

        // 5) Write JWKS JSON (pretty)
        var json = JsonSerializer.Serialize(jwks, new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        });
        File.WriteAllText(jwksPath, json, new UTF8Encoding(false));

        // 6) Summary
        Console.WriteLine("Generated files:");
        Console.WriteLine($" - {privatePemPath}");
        Console.WriteLine($" - {publicPemPath}");
        Console.WriteLine($" - {jwksPath}");
        Console.WriteLine($"\nYour KID: {kid}");
        Console.WriteLine("\nNext steps:");
        Console.WriteLine("1) Host jwks.json at a PUBLIC HTTPS URL (GitHub Pages / S3 / Vercel / Netlify).");
        Console.WriteLine("2) Update eCW Dev Portal → Sandbox Configuration → JWKS URL (no localhost).");
        Console.WriteLine("3) Use this KID in your JWT header when signing with RS384 for client_assertion.");
        Console.WriteLine("4) Postman token endpoint:");
        Console.WriteLine("   https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token");
    }

    // ----- Helpers -----

    static string PemEncode(string label, byte[] derBytes)
    {
        var b64 = Convert.ToBase64String(derBytes);
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");
        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        }
        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }

    static string ToBase64Url(byte[] bytes)
    {
        // Base64URL (no padding, + -> -, / -> _)
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    static string Sha256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    // ----- Models -----

    public class Jwks
    {
        [JsonPropertyName("keys")]
        public Jwk[] Keys { get; set; } = Array.Empty<Jwk>();
    }

    public class Jwk
    {
        [JsonPropertyName("kty")] public string Kty { get; set; } = "RSA";
        [JsonPropertyName("alg")] public string? Alg { get; set; } = "RS384";
        [JsonPropertyName("n")] public string N { get; set; } = "";
        [JsonPropertyName("e")] public string E { get; set; } = "AQAB";
        [JsonPropertyName("use")] public string Use { get; set; } = "sig";
        [JsonPropertyName("key_ops")] public string[]? KeyOps { get; set; } = new[] { "verify" }; // optional
        [JsonPropertyName("ext")] public bool? Ext { get; set; } = true;                      // optional
        [JsonPropertyName("kid")] public string Kid { get; set; } = "";
    }
}