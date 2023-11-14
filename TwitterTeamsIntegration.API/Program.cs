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
    var decryptor = new Decryptor() { Certificate = wrapper.Certificate };

    foreach (var notification in payload.Value)
    {
        string decryptedResourceData = decryptor.Decrypt(
            notification.EncryptedContent.Data,
            notification.EncryptedContent.DataSignature,
            notification.EncryptedContent.DataKey
        );
    }


    return Results.Ok();
});

app.Run();

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