using System;
using System.Collections.Generic;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace EcwSmartM2M
{
    class Program
    {
        // ====== ECW CONFIG (YOUR VALUES) ======
        private static readonly string ClientId = "GS1D-SX867Tndyc3u_Z_8DAJmlNuUhrRbbpElDFNeBU";
        private static readonly string TokenEndpoint = "https://staging-oauthserver.ecwcloud.com/oauth/oauth2/token";
        private static readonly string FhirBaseUrl = "https://staging-fhir.ecwcloud.com/fhir/r4/FFBJCD";
        private static readonly string Kid = "c4d2f0222e3d5b8fff6eabb46d4b870aea13de3b4ba97fbc7f72263af547e1c2";

        // Use system-level scopes for Backend Services apps.
        private static readonly string Scope = "system/DocumentReference.read system/Group.read";

        // Your private key PEM (PKCS#8 or PKCS#1)
        private static readonly string PrivateKeyPemPath =
            @"c:\users\rbhatt\OneDrive - OptumCare\Desktop\eCW_POC\Keys\private_key.pem";

        static async Task Main(string[] args)
        {
            Console.WriteLine("eCW SMART Backend (M2M) – Client Credentials with JWT (RS384)");

            try
            {
                // 1) Build a JWT client assertion (RS384)
                var clientAssertionJwt = CreateClientAssertionJwt(
                    clientId: ClientId,
                    audience: TokenEndpoint,
                    privateKeyPemPath: PrivateKeyPemPath,
                    kid: Kid
                );
                Console.WriteLine("Generated client_assertion (JWT) successfully.");

                // 2) Exchange JWT for Access Token
                var tokenResponse = await RequestAccessTokenAsync(
                    tokenEndpoint: TokenEndpoint,
                    clientId: ClientId,
                    clientAssertionJwt: clientAssertionJwt,
                    scope: Scope
                );

                Console.WriteLine("\n=== Token Response (raw) ===");
                Console.WriteLine(tokenResponse.RawJson);

                if (string.IsNullOrWhiteSpace(tokenResponse.AccessToken))
                {
                    Console.WriteLine("\nNo access_token received.");
                    return;
                }

                Console.WriteLine("\nAccess Token obtained");
                Console.WriteLine($"expires_in: {tokenResponse.ExpiresIn}s, token_type: {tokenResponse.TokenType}");

                // Optional: decode to verify claims (aud, scope, etc.)
                PrintAccessTokenClaims(tokenResponse.AccessToken);

                // =============================
                // 3) $export poll → manifest
                // =============================

                // TODO: Paste the EXACT job_id that worked in Postman (no quotes / %27)
                var jobId = "647f3e16-5c88-4df7-910a-4ecde48f30fb";

                // TODO (optional): If eCW provided affinity cookies, paste them here; else set to null
                string? cookies =
                    "ApplicationGatewayAffinity=a9bfd5e4e713f027765a54dc27c8593a; ApplicationGatewayAffinityCORS=a9bfd5e4e713f027765a54dc27c8593a";
                // or: null;

                var (statusCode, manifestJson) = await CallExportPollAsync(
                    accessToken: tokenResponse.AccessToken,
                    jobId: jobId,
                    cookieHeader: cookies
                );

                if (statusCode != 200)
                {
                    Console.WriteLine("\nPoll did not return 200. Stopping.");
                    return;
                }

                // =============================
                // 4) Parse manifest → DocRef URL
                // =============================
                var docRefDownloadUrl = ExtractOutputUrl(manifestJson, resourceType: "DocumentReference");
                if (string.IsNullOrWhiteSpace(docRefDownloadUrl))
                {
                    Console.WriteLine("\n(No DocumentReference output found in manifest.)");
                    Console.WriteLine("Manifest was:\n" + manifestJson);
                    return;
                }

                Console.WriteLine($"\nDocumentReference NDJSON download URL:\n{docRefDownloadUrl}");

                // Replace &amp; with & (manifest HTML-escapes ampersands)
                docRefDownloadUrl = docRefDownloadUrl.Replace("&amp;", "&");

                // =============================
                // 5) Download & Parse NDJSON
                // =============================
                var ndjsonPath = "DocumentReference.ndjson";
                await DownloadBulkFileAsync(
                    accessToken: tokenResponse.AccessToken,
                    downloadUrl: docRefDownloadUrl,
                    outputPath: ndjsonPath,
                    cookieHeader: cookies
                );

                await ParseDocumentReferenceNdjsonAsync(ndjsonPath, maxToPrint: 10);
            }
            catch (Exception ex)
            {
                Console.WriteLine("\n❌ Error:");
                Console.WriteLine(ex.ToString());
            }
        }

        // ------------------------------------------------------
        // CLIENT ASSERTION (RS384)  iss=sub=client_id, aud=token
        // ------------------------------------------------------
        private static string CreateClientAssertionJwt(string clientId, string audience, string privateKeyPemPath, string kid)
        {
            if (!File.Exists(privateKeyPemPath))
                throw new FileNotFoundException($"Private key not found at: {privateKeyPemPath}");

            var pem = File.ReadAllText(privateKeyPemPath, Encoding.UTF8);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem.ToCharArray());

            var securityKey = new RsaSecurityKey(rsa) { KeyId = kid };
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha384);

            var now = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, clientId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
            };

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = clientId,                    // iss
                Subject = new ClaimsIdentity(claims), // sub + jti
                Audience = audience,                  // aud = token endpoint
                NotBefore = now.UtcDateTime,
                IssuedAt = now.UtcDateTime,
                Expires = now.AddMinutes(5).UtcDateTime,
                SigningCredentials = signingCredentials
            };

            var handler = new JwtSecurityTokenHandler();
            var token = handler.CreateJwtSecurityToken(tokenDescriptor);
            token.Header["typ"] = "JWT";
            return handler.WriteToken(token);
        }

        // ------------------------------------------------------
        // TOKEN (client_credentials + JWT-bearer)
        // ------------------------------------------------------
        private static async Task<TokenResult> RequestAccessTokenAsync(string tokenEndpoint, string clientId, string clientAssertionJwt, string scope)
        {
            using var http = new HttpClient();

            var form = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", clientAssertionJwt },
                { "client_id", clientId },
                { "scope", scope }
            };

            using var content = new FormUrlEncodedContent(form);
            var resp = await http.PostAsync(tokenEndpoint, content);
            var raw = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                Console.WriteLine($"\nToken endpoint returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");
                return new TokenResult { RawJson = raw };
            }

            try
            {
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;
                return new TokenResult
                {
                    RawJson = raw,
                    AccessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null,
                    TokenType = root.TryGetProperty("token_type", out var tt) ? tt.GetString() : null,
                    ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt32() : 0
                };
            }
            catch
            {
                return new TokenResult { RawJson = raw };
            }
        }

        // ------------------------------------------------------
        // $export poll → returns (statusCode, body)
        // ------------------------------------------------------
        private static async Task<(int StatusCode, string Body)> CallExportPollAsync(
            string accessToken,
            string jobId,
            string? cookieHeader = null
        )
        {
            jobId = (jobId ?? string.Empty).Trim().Trim('\'', '"');
            if (jobId.EndsWith("%27", StringComparison.Ordinal))
                jobId = jobId.Substring(0, jobId.Length - 3);

            var safeJobId = Uri.EscapeDataString(jobId);
            var url = $"{FhirBaseUrl}/$export-poll-location?job_id={safeJobId}";

            using var http = new HttpClient();
            http.DefaultRequestHeaders.Clear();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            http.DefaultRequestHeaders.Accept.Clear();
            // Poll/status endpoints often return plain JSON
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (!string.IsNullOrWhiteSpace(cookieHeader))
            {
                http.DefaultRequestHeaders.Add("Cookie", cookieHeader);
            }

            Console.WriteLine($"\nCalling FHIR: GET {url}");
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();

            Console.WriteLine($"\nFHIR Response HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}");
            Console.WriteLine(body);

            return ((int)resp.StatusCode, body);
        }

        // ------------------------------------------------------
        // Extract the first output URL for a given resourceType
        // ------------------------------------------------------
        private static string? ExtractOutputUrl(string manifestJson, string resourceType)
        {
            try
            {
                using var doc = JsonDocument.Parse(manifestJson);
                var root = doc.RootElement;

                if (!root.TryGetProperty("output", out var output) || output.ValueKind != JsonValueKind.Array)
                    return null;

                foreach (var item in output.EnumerateArray())
                {
                    var typeOk = item.TryGetProperty("type", out var t) && (t.GetString() ?? "") == resourceType;
                    var urlOk = item.TryGetProperty("url", out var u) && !string.IsNullOrWhiteSpace(u.GetString());
                    if (typeOk && urlOk)
                        return u.GetString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"(warn) Failed to parse manifest JSON: {ex.Message}");
            }
            return null;
        }

        // ------------------------------------------------------
        // Download NDJSON file
        // ------------------------------------------------------
        private static async Task DownloadBulkFileAsync(string accessToken, string downloadUrl, string outputPath, string? cookieHeader = null)
        {
            // Replace HTML &amp; with &
            downloadUrl = (downloadUrl ?? string.Empty).Replace("&amp;", "&");

            using var http = new HttpClient();
            http.DefaultRequestHeaders.Clear();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            http.DefaultRequestHeaders.Accept.Clear();
            // Bulk spec uses NDJSON
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/fhir+ndjson"));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/x-ndjson"));
            http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            if (!string.IsNullOrWhiteSpace(cookieHeader))
            {
                http.DefaultRequestHeaders.Add("Cookie", cookieHeader);
            }

            Console.WriteLine($"\nDownloading NDJSON: GET {downloadUrl}");
            var resp = await http.GetAsync(downloadUrl);
            resp.EnsureSuccessStatusCode();

            // Save directly to file
            await using var fs = File.Create(outputPath);
            await resp.Content.CopyToAsync(fs);

            Console.WriteLine($"Saved → {outputPath}");
        }

        // ------------------------------------------------------
        // Parse DocumentReference NDJSON and print a few lines
        // ------------------------------------------------------
        private static async Task ParseDocumentReferenceNdjsonAsync(string ndjsonPath, int maxToPrint = 5)
        {
            Console.WriteLine($"\nParsing NDJSON: {ndjsonPath}");
            if (!File.Exists(ndjsonPath))
            {
                Console.WriteLine("File not found.");
                return;
            }

            int printed = 0;
            int lineNo = 0;

            // Read lines efficiently
            using var fs = new FileStream(ndjsonPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, Encoding.UTF8);

            while (!sr.EndOfStream)
            {
                var line = await sr.ReadLineAsync();
                lineNo++;
                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("resourceType", out var rt) || (rt.GetString() ?? "") != "DocumentReference")
                        continue;

                    string id = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                    string status = root.TryGetProperty("status", out var st) ? st.GetString() ?? "" : "";
                    string date = root.TryGetProperty("date", out var dt) ? dt.GetString() ?? "" : "";
                    string typeDisplay = ExtractDocRefType(root);

                    Console.WriteLine($"DocRef/{id} | Status: {status} | Date: {date} | Type: {typeDisplay}");

                    if (++printed >= maxToPrint) break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"(warn) parse error at line {lineNo}: {ex.Message}");
                }
            }

            Console.WriteLine($"Printed {printed} DocumentReference(s).");
        }

        private static string ExtractDocRefType(JsonElement docRef)
        {
            try
            {
                if (docRef.TryGetProperty("type", out var type) &&
                    type.TryGetProperty("coding", out var coding) &&
                    coding.ValueKind == JsonValueKind.Array)
                {
                    foreach (var c in coding.EnumerateArray())
                    {
                        if (c.TryGetProperty("display", out var disp)) return disp.GetString() ?? "";
                        if (c.TryGetProperty("code", out var code)) return code.GetString() ?? "";
                    }
                }
            }
            catch { /* ignore */ }
            return "";
        }

        // ------------------------------------------------------
        // Debug helper: decode access token (no signature validation)
        // ------------------------------------------------------
        private static void PrintAccessTokenClaims(string jwt)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(jwt);

                Console.WriteLine("\n-- Decoded Access Token Claims --");
                foreach (var c in token.Claims)
                    Console.WriteLine($"{c.Type}: {c.Value}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n(Warning) Could not decode access token locally: {ex.Message}");
            }
        }

        // ------------------------------------------------------
        // Models
        // ------------------------------------------------------
        private class TokenResult
        {
            public string RawJson { get; set; }
            public string AccessToken { get; set; }
            public string TokenType { get; set; }
            public int ExpiresIn { get; set; }
        }
    }
}