using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Serialization.Json;
using Serilog;
using TwitterTeamsIntegration.API;
using WebApplication = Microsoft.AspNetCore.Builder.WebApplication;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();

builder.Services.Configure<MicrosoftGraphOptions>(builder.Configuration.GetSection("MicrosoftGraph"));
builder.Services.AddScoped<MicrosoftGraphFacade>(); //Can this be a singleton?

builder.Host.UseSerilog();

var app = builder.Build();

app.MapGet("/", async (MicrosoftGraphFacade facade) => await facade.Subscribe());
app.MapPost("/notify", async (HttpRequest request, ILogger<Program> logger, MicrosoftGraphFacade facade) =>
{
    logger.LogInformation("Request: ");

    if (request.Query.TryGetValue("validationToken", out var validationToken))
    {
        return Results.Text(validationToken, statusCode: 200);
    }

    var jsonDocument = await JsonDocument.ParseAsync(request.Body);
    var parseNode = new JsonParseNode(jsonDocument.RootElement.Clone());
    var payload =
        parseNode.GetObjectValue<ChangeNotificationCollection>(
            ChangeNotificationCollection.CreateFromDiscriminatorValue);
    
    var wrapper = new CertificateWrapper();
    
    using var rsaPrivateKey = wrapper.Certificate.GetRSAPrivateKey();

    if (rsaPrivateKey == null)
    {
        throw new Exception("Null key");
    }

    RSAParameters rsaParams = rsaPrivateKey.ExportParameters(true);

    // Create a new RSACryptoServiceProvider and import the parameters
    RSACryptoServiceProvider provider = new RSACryptoServiceProvider(rsaPrivateKey.KeySize);
    provider.ImportParameters(rsaParams);

    foreach (var notification in payload.Value)
    {
        string decryptedResourceData;

        byte[] encryptedSymmetricKey = Convert.FromBase64String(notification.EncryptedContent.DataKey);
        byte[] decryptedSymmetricKey = provider.Decrypt(encryptedSymmetricKey, fOAEP: true);

        byte[] encryptedPayload = Encoding.UTF8.GetBytes(notification.EncryptedContent.Data);
        byte[] expectedSignature = Encoding.UTF8.GetBytes(notification.EncryptedContent.DataSignature);
        byte[] actualSignature;

        using (HMACSHA256 hmac = new HMACSHA256(decryptedSymmetricKey))
        {
            actualSignature = hmac.ComputeHash(encryptedPayload);
        }

        if (actualSignature.SequenceEqual(expectedSignature))
        {
            // Continue with decryption of the encryptedPayload.
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Key = decryptedSymmetricKey;
            aesProvider.Padding = PaddingMode.PKCS7;
            aesProvider.Mode = CipherMode.CBC;

            // Obtain the intialization vector from the symmetric key itself.
            int vectorSize = 16;
            byte[] iv = new byte[vectorSize];
            Array.Copy(decryptedSymmetricKey, iv, vectorSize);
            aesProvider.IV = iv;

            // Decrypt the resource data content.
            using (var decryptor = aesProvider.CreateDecryptor())
            {
                using (MemoryStream msDecrypt = new MemoryStream(encryptedPayload))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decryptedResourceData = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            // decryptedResourceData now contains a JSON string that represents the resource.
        }
        else
        {
            // Do not attempt to decrypt encryptedPayload. Assume notification payload has been tampered with and investigate.
        }
    }


    return Results.Ok();
});

app.Run();

internal class CertificateWrapper
{
    private const string PublicKey = @"-----BEGIN CERTIFICATE-----
MIIEujCCAqICCQDbO6i7sCWq1TANBgkqhkiG9w0BAQsFADAfMQswCQYDVQQGEwJV
UzEQMA4GA1UECAwHQ2hpY2FnbzAeFw0yMzEwMzEyMjU2MDBaFw0yNDEwMzAyMjU2
MDBaMB8xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdDaGljYWdvMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEAuBJIkcnU5++GR53CoRdImBRoRmGdtsM4JSaq
+258lhGXdz+ETF/Td0hSUWZ0mHNA1+5byPr5CoxenaI9HUK9Aw3p/j+sy0sdRrDj
frpwE8XsoRvPU+Sy+Ut7CTUyaMH/6Y1VsFsOqeUHUPbzK6WM7h8cQh1I2Ps1egXT
K8r8Y7w8c4ooXkCL3Hk4YrB+Uu3aA0UbO4kLVbVnInZAVQ3zqYY+fpjQXuNpckBU
gFbGFHAfdIEIz3mwLJqB+HSmXLSQpILcJ5wkZQzxtQoa+uWemGAJXsqv2V2m8fpB
DzxSuRgskNyF77WlXUKDkEnh9UE+OLe3ROQmz3YMJ2ZoAORBY0bqINojdvPrHFEX
y/bubX5U8wviTh2SAhzcXBIAfTGkd0wdmCGRsFLunMa0DqR/kxQQ1H+kyD5cBlWf
c/lsd91Z16AkifbxGhOxfSnTkGNVf3yhceCUL+EIQ79IkrDmw7iq6iSYCsutAQhq
nh0hsYXKDBB+4K0PqmVrQ0jByIXORRn37oSw8VBrkaBKQg3e6l9F9TEtzvUPpd2A
8NX+M29DQl69bONbwpr7LYwJsb4O4jGbS5hL45OIiuYy8gndgFTqw9qbdFRjUFKB
OSZz0v7F2MyLT73Ye3kRmcp3m+LEK571u2oMz3nxNCGWUtEpdiN6oRmMoyRk2XaT
sm6BzQsCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAsMD40iT2T0Q/Kn6fJp+8cEPh
Zphc8iyGDGGkc/IOocbeIWJ1VjmLr2NV1JdvW+OZ0RHpnlNyINC2Bvz95vNBEV2m
YcP8kWOgMBFJRuhWO7Hwvuqzu0sBQ4JjC694SrtD1kqUxdRusLfUho1M2+9Emcyc
5ygMZTFLAaXLSPUADaS+7StgRVi4NKQmbuZ+ePG76psGgYl4qd4VidJ5Mq6/4neT
PIXDfbyANbr6tRXKUfOD7rkxr4slsZVSs02ingfKJB1ywfDqtXpUWcqJ3D9JOU8X
WJZkBTWYHstVFH4yGWvblhzrkOsb9pBHz0bJpOLFKTtnEFdZaPFs0qcB+cB74TzN
+nEFnrO+qbRQ3jwLL3KvZsPBkKHyeRJcrHuQ89qFJbm4kna9oxotkFQy9iGoKiez
gj3UGBlopF2Sn5AQHDfTzsx04+q6L1nN46kM9RyZL2MQwUQF6BbhRm6T1oI0O7wB
tv9Gbbo6fALW5U7v+rWiOeLbBdXECUjv6OHTUGI+w0R6FZk2ArDESYMUOnvUO3Zr
v/prBGseaVfrT4DcZGPDX8qh86X4GtCuQz4TqaIhWDPZBh50G0o+BYk4gwlR9Lda
grxvX8Nrclr4XAUd4CiZwK7ITyMBTnAlfr4jP6dhkJgE9aR8HapnOQ94cKT87UKE
OL+OthHSYAtrycpU/HA=
-----END CERTIFICATE-----";

    private const string PrivateKey = @"-----BEGIN PRIVATE KEY-----
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
RPe22l739ppL5N4AOTc7wxM3VysR2uSp
-----END PRIVATE KEY-----";
    
    

    private const string PrivateKey2 = @"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
RPe22l739ppL5N4AOTc7wxM3VysR2uSp";
    
    public X509Certificate2 Certificate { get; }
    
    public CertificateWrapper()
    {
        Certificate = new X509Certificate2(Encoding.UTF8.GetBytes(PublicKey));

        using var privateKey = RSA.Create();
        privateKey.ImportPkcs8PrivateKey(Convert.FromBase64String(PrivateKey2), out _);
        Certificate = Certificate.CopyWithPrivateKey(privateKey);
    }
}

internal class MicrosoftGraphFacade
{
    private readonly IOptions<MicrosoftGraphOptions> _config;
    private readonly GraphServiceClient _client;
    private readonly ClientSecretCredential _credential;

    private const string DefaultScope = "https://graph.microsoft.com/.default";

    public MicrosoftGraphFacade(IOptions<MicrosoftGraphOptions> config)
    {
        _config = config;
        _credential =
            new ClientSecretCredential(_config.Value.TenantId, config.Value.ClientId, config.Value.ClientSecret);

        _client = new GraphServiceClient(_credential, new[] { DefaultScope });
    }

    public async Task<AccessToken> GetAccessToken()
    {
        var scopes = new[] { DefaultScope };
        var context = new TokenRequestContext(scopes);
        var response = await _credential.GetTokenAsync(context);
        return response;
    }

    public async Task<Subscription?> Subscribe()
    {
        await DeleteAllSubscriptions();

        var base64Encoded = Convert.ToBase64String(new CertificateWrapper().Certificate.Export(X509ContentType.Cert));
        
        var subscription = new Subscription
        {
            ChangeType = "created",
            NotificationUrl = _config.Value.NotificationUrl,
            Resource = "/teams/getAllMessages", //Needs to target specific chat instead.
            ExpirationDateTime = DateTimeOffset.UtcNow.AddHours(1),
            ClientState = "SomeState",
            EncryptionCertificate = base64Encoded,
            EncryptionCertificateId = "SomeId",
            IncludeResourceData = true,
        };

        var newSubscription = await _client.Subscriptions.PostAsync(subscription);

        return newSubscription;
    }

    public async Task DeleteAllSubscriptions()
    {
        //Mind paging, might need a PageIterator
        var subscriptions = await _client.Subscriptions.GetAsync();

        foreach (var subscription in subscriptions.Value)
        {
            await _client.Subscriptions[subscription.Id].DeleteAsync();
        }
    }
}