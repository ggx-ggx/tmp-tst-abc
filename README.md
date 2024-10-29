# tmp-tst-abc


ps-> 19713a9c6fD$aa#

```csharp
using System;
using RestSharp;

public class OktaApiHelper
{
    private readonly string baseUrl;
    private readonly string clientId;
    private readonly string clientSecret;

    public OktaApiHelper(string baseUrl, string clientId, string clientSecret)
    {
        this.baseUrl = baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    private RestClient CreateRestClient()
    {
        return new RestClient(baseUrl);
    }

    public string GetAuthorizationHeader()
    {
        var base64ClientIdSecret = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
        return $"Basic {base64ClientIdSecret}";
    }

    public string GetAccessToken(string username, string password, string scope)
    {
        var client = CreateRestClient();
        var request = new RestRequest("/token", Method.POST);
        request.AddHeader("Authorization", GetAuthorizationHeader());
        request.AddParameter("grant_type", "password");
        request.AddParameter("username", username);
        request.AddParameter("password", password);
        request.AddParameter("scope", scope);

        var response = client.Execute(request);
        if (response.IsSuccessful)
        {
            dynamic jsonResponse = Newtonsoft.Json.JsonConvert.DeserializeObject(response.Content);
            return jsonResponse.access_token;
        }
        else
        {
            throw new Exception($"Failed to get access token: {response.Content}");
        }
    }

    public void RevokeAccessToken(string accessToken)
    {
        var client = CreateRestClient();
        var request = new RestRequest("/revoke", Method.POST);
        request.AddParameter("token", accessToken);
        request.AddParameter("token_type_hint", "access_token");

        client.Execute(request);
    }

    public void RevokeRefreshToken(string refreshToken)
    {
        var client = CreateRestClient();
        var request = new RestRequest("/revoke", Method.POST);
        request.AddParameter("token", refreshToken);
        request.AddParameter("token_type_hint", "refresh_token");

        client.Execute(request);
    }
}

/****


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .ConfigureApplicationPartManager(manager =>
    {
        if (!builder.Environment.IsDevelopment())
        {
            // Exclude the development-only controller from non-development environments
            var controllerType = typeof(MyDevOnlyController).GetTypeInfo();
            var part = manager.ApplicationParts.FirstOrDefault(p => p.Name == controllerType.Assembly.GetName().Name);
            if (part != null && part is AssemblyPart assemblyPart)
            {
                assemblyPart.Types.Remove(controllerType);
            }
        }
    });

var app = builder.Build();

app.UseAuthorization();

app.MapControllers();

app.Run();


****/


var oktaHelper = new OktaApiHelper("https://your-okta-domain/oauth2/default", "your-client-id", "your-client-secret");
var accessToken = oktaHelper.GetAccessToken("username", "password", "openid profile");
// Use the access token as needed
oktaHelper.RevokeAccessToken(accessToken);
```

**Authentication Endpoints**:
    
    *   `/authn`: Initiates authentication flows.
    *   `/sessions`: Manages user sessions.
    *   `/users`: Manages user authentication and credentials.
    *   `/groups`: Manages groups and group membership.
*   **Authorization Endpoints**:
    
    *   `/authorize`: Initiates OAuth 2.0 authorization flows.
    *   `/token`: Issues OAuth 2.0 tokens (access token, refresh token).
    *   `/introspect`: Introspects an OAuth 2.0 token.
    *   `/revoke`: Revokes OAuth 2.0 tokens.
    *   `/logout`: Logs out users and ends sessions.
    *   `/scopes`: Manages OAuth 2.0 scopes.
*   **Multi-Factor Authentication (MFA) Endpoints**:
    
    *   `/factors`: Manages MFA factors for users.
    *   `/verify`: Verifies MFA factors during authentication.
*   **Password Policy Endpoints**:
    
    *   `/password`: Manages password-related operations (reset, change, etc.).
*   **Social Authentication Endpoints**:
    
    *   `/authorizationServers`: Manages authorization servers for social authentication.
    *   `/identityProviders`: Manages identity providers for social authentication.
*   **Device and Session Management**:
    
    *   `/sessions`: Manages user sessions and session cookies.
    *   `/sessions/me`: Retrieves information about the current user's session.
    *   `/devices`: Manages trusted devices for MFA.
*   **User Consent and Authorization**:
    
    *   `/consent`: Handles user consent for OAuth 2.0 applications.
    *   `/authorizations`: Manages application authorizations and permissions.
*   **Security Events**:
    
    *   `/logs`: Retrieves security logs and audit trails.
    *   `/events`: Manages event hooks for security events.
*   **User Management and Profiles**:
    
    *   `/users`: Manages user accounts, profiles, and attributes.
    *   `/groups`: Manages groups, roles, and group memberships.
*   **Token Management**:
    
    *   `/tokens`: Manages OAuth 2.0 tokens, token lifetimes, and policies.



Install-Package Microsoft.IdentityModel.JsonWebTokens


```
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

public class OktaJwtVerifier
{
    private readonly string issuer;
    private readonly ConfigurationManager<OpenIdConnectConfiguration> configurationManager;

    public OktaJwtVerifier(string issuer, string jwksUri)
    {
        this.issuer = issuer;
        this.configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            jwksUri,
            new OpenIdConnectConfigurationRetriever());
    }

    public async Task<SecurityToken> VerifyJwtTokenAsync(string jwtToken)
    {
        var openIdConfig = await configurationManager.GetConfigurationAsync();

        var validationParameters = new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = openIdConfig.TokenEndpoint,
            IssuerSigningKeys = openIdConfig.SigningKeys,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken validatedToken;

        try
        {
            tokenHandler.ValidateToken(jwtToken, validationParameters, out validatedToken);
            return validatedToken;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to validate token: {ex.Message}");
            throw;
        }
    }
}



var oktaVerifier = new OktaJwtVerifier("https://your-okta-domain/oauth2/default", "https://your-okta-domain/oauth2/default/v1/keys");
string jwtToken = "your_jwt_token_here";

try
{
    var validatedToken = await oktaVerifier.VerifyJwtTokenAsync(jwtToken);
    Console.WriteLine("Token is valid!");
    // Optionally, you can access token claims from validatedToken.Claims
}
catch (Exception ex)
{
    Console.WriteLine($"Token validation failed: {ex.Message}");
}


using System;

[AttributeUsage(AttributeTargets.Property)]
public class SensitiveDataAttribute : Attribute
{
    public int MaskLength { get; }

    public SensitiveDataAttribute(int maskLength = 0)
    {
        MaskLength = maskLength; // 0 means remove the property; >0 means mask the first N characters
    }
}


using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Linq;
using System.Reflection;

public class SensitiveDataContractResolver : DefaultContractResolver
{
    private readonly bool _maskSensitiveData;

    public SensitiveDataContractResolver(bool maskSensitiveData)
    {
        _maskSensitiveData = maskSensitiveData;
    }

    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        var properties = base.CreateProperties(type, memberSerialization);

        foreach (var property in properties)
        {
            var sensitiveDataAttribute = property.AttributeProvider.GetAttributes(true)
                .OfType<SensitiveDataAttribute>()
                .FirstOrDefault();

            if (sensitiveDataAttribute != null)
            {
                if (sensitiveDataAttribute.MaskLength == 0)
                {
                    // If mask length is 0, skip serialization of this property.
                    property.ShouldSerialize = _ => false;
                }
                else if (sensitiveDataAttribute.MaskLength > 0 && _maskSensitiveData)
                {
                    // If mask length is greater than 0, apply masking during serialization.
                    property.ValueProvider = new MaskedValueProvider(property.ValueProvider, sensitiveDataAttribute.MaskLength);
                }
            }
        }

        return properties;
    }
}

public class MaskedValueProvider : IValueProvider
{
    private readonly IValueProvider _innerProvider;
    private readonly int _maskLength;

    public MaskedValueProvider(IValueProvider innerProvider, int maskLength)
    {
        _innerProvider = innerProvider;
        _maskLength = maskLength;
    }

    public object GetValue(object target)
    {
        var originalValue = _innerProvider.GetValue(target)?.ToString();
        if (originalValue == null || originalValue.Length <= _maskLength)
        {
            return new string('*', originalValue?.Length ?? 0); // Fully mask if the string is too short
        }

        // Mask only the first N characters, and keep the rest
        var maskedValue = new string('*', _maskLength) + originalValue.Substring(_maskLength);
        return maskedValue;
    }

    public void SetValue(object target, object value)
    {
        _innerProvider.SetValue(target, value);
    }
}



using Newtonsoft.Json;

public class Program
{
    public static void Main()
    {
        var user = new UserData
        {
            Username = "johndoe",
            Email = "john@example.com",
            SSN = "123-45-6789",
            Address = "123 Main St"
        };

        // Serialize with masking (for logging)
        string jsonWithMasking = JsonConvert.SerializeObject(user, new JsonSerializerSettings
        {
            ContractResolver = new SensitiveDataContractResolver(maskSensitiveData: true),
            Formatting = Formatting.Indented
        });

        // Serialize without masking (for API response)
        string jsonWithoutMasking = JsonConvert.SerializeObject(user, new JsonSerializerSettings
        {
            ContractResolver = new SensitiveDataContractResolver(maskSensitiveData: false),
            Formatting = Formatting.Indented
        });

        Console.WriteLine("With Masking:\n" + jsonWithMasking);
        Console.WriteLine("Without Masking:\n" + jsonWithoutMasking);
    }
}







using System;

public enum NonStringHandling
{
    Drop,    // Drop non-string properties
    Default  // Set non-string properties to default value
}

[AttributeUsage(AttributeTargets.Property)]
public class SensitiveDataAttribute : Attribute
{
    public int MaskLength { get; }
    public NonStringHandling HandleNonString { get; }

    public SensitiveDataAttribute(int maskLength = 0, NonStringHandling handleNonString = NonStringHandling.Drop)
    {
        MaskLength = maskLength;
        HandleNonString = handleNonString; // Handle non-string properties (Drop or Default)
    }
}


using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Linq;

public class SensitiveDataContractResolver : DefaultContractResolver
{
    private readonly bool _maskSensitiveData;

    public SensitiveDataContractResolver(bool maskSensitiveData)
    {
        _maskSensitiveData = maskSensitiveData;
    }

    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        var properties = base.CreateProperties(type, memberSerialization);

        foreach (var property in properties)
        {
            var sensitiveDataAttribute = property.AttributeProvider.GetAttributes(true)
                .OfType<SensitiveDataAttribute>()
                .FirstOrDefault();

            if (sensitiveDataAttribute != null)
            {
                if (property.PropertyType != typeof(string))
                {
                    if (sensitiveDataAttribute.HandleNonString == NonStringHandling.Drop)
                    {
                        // Drop non-string properties with PII
                        property.ShouldSerialize = _ => false;
                    }
                    else if (sensitiveDataAttribute.HandleNonString == NonStringHandling.Default)
                    {
                        // Set non-string properties to default value
                        property.ValueProvider = new DefaultValueProvider(property.ValueProvider, property.PropertyType);
                    }
                }
                else
                {
                    if (sensitiveDataAttribute.MaskLength == 0)
                    {
                        // Completely remove the string property from serialization
                        property.ShouldSerialize = _ => false;
                    }
                    else if (sensitiveDataAttribute.MaskLength > 0 && _maskSensitiveData)
                    {
                        // Apply masking to string properties
                        property.ValueProvider = new MaskedValueProvider(property.ValueProvider, sensitiveDataAttribute.MaskLength);
                    }
                }
            }
        }

        return properties;
    }
}


public class DefaultValueProvider : IValueProvider
{
    private readonly IValueProvider _innerProvider;
    private readonly Type _propertyType;

    public DefaultValueProvider(IValueProvider innerProvider, Type propertyType)
    {
        _innerProvider = innerProvider;
        _propertyType = propertyType;
    }

    public object GetValue(object target)
    {
        // Set to the default value for the property type
        return GetDefaultValue(_propertyType);
    }

    public void SetValue(object target, object value)
    {
        _innerProvider.SetValue(target, value);
    }

    private object GetDefaultValue(Type type)
    {
        return type.IsValueType ? Activator.CreateInstance(type) : null;
    }
}





```



thius is a test



```yaml


**# Use root/example as user/password credentials
version: '3.1'

services:

  mongo:
    image: mongo
    restart: always
    ports:
        - "27017:27017"    

  mongo-express:
    image: mongo-express
    restart: always
    ports:
      - 8081:8081

  redis:
    image: redis
    restart: always
    ports:
      - 6379:6379
    volumes:
      - ./config/redis.conf:/redis.conf
    command: [ "redis-server", "/redis.conf" ]

  gxweb:
    image: rameshkumarcd/gxweb
    ports:
        - "8000:80"
        - "44348:443"
    depends_on:
        - mongo
    links:
      - mongo**



```









```csharp
[AttributeUsage(AttributeTargets.Class, Inherited = true)]
public class SensitiveDataHandlerAttribute : Attribute
{
}


using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Linq;

public class SensitiveDataContractResolver : DefaultContractResolver
{
    private readonly bool _maskSensitiveData;

    public SensitiveDataContractResolver(bool maskSensitiveData)
    {
        _maskSensitiveData = maskSensitiveData;
    }

    protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
    {
        // Check if the class has the SensitiveDataHandler attribute
        if (!type.GetCustomAttributes(typeof(SensitiveDataHandlerAttribute), true).Any())
        {
            // If the attribute is missing, return a property with a warning message
            var warningProperty = new JsonProperty
            {
                PropertyName = type.Name.ToLower(),
                PropertyType = typeof(string),
                ValueProvider = new StaticValueProvider($"Warning: {type.Name} class not masked for sensitive data. Ignored."),
                Readable = true,
                Writable = false,
                ShouldSerialize = instance => true // Always serialize the warning message
            };

            return new List<JsonProperty> { warningProperty };
        }

        // Otherwise, proceed with normal serialization
        var properties = base.CreateProperties(type, memberSerialization);

        foreach (var property in properties)
        {
            var sensitiveDataAttribute = property.AttributeProvider.GetAttributes(true)
                .OfType<SensitiveDataAttribute>()
                .FirstOrDefault();

            if (sensitiveDataAttribute != null)
            {
                if (property.PropertyType != typeof(string))
                {
                    // Handle non-string properties (drop or set to default)
                    if (sensitiveDataAttribute.HandleNonString == NonStringHandling.Drop)
                    {
                        property.ShouldSerialize = _ => false;
                    }
                    else if (sensitiveDataAttribute.HandleNonString == NonStringHandling.Default)
                    {
                        property.ValueProvider = new DefaultValueProvider(property.ValueProvider, property.PropertyType);
                    }
                }
                else
                {
                    if (sensitiveDataAttribute.MaskLength == 0)
                    {
                        property.ShouldSerialize = _ => false;
                    }
                    else if (sensitiveDataAttribute.MaskLength > 0 && _maskSensitiveData)
                    {
                        property.ValueProvider = new MaskedValueProvider(property.ValueProvider, sensitiveDataAttribute.MaskLength);
                    }
                }
            }
        }

        return properties;
    }
}

public class StaticValueProvider : IValueProvider
{
    private readonly object _value;

    public StaticValueProvider(object value)
    {
        _value = value;
    }

    public object GetValue(object target) => _value;

    public void SetValue(object target, object value)
    {
        // No-op since it's a static value
    }
}

public class DefaultValueProvider : IValueProvider
{
    private readonly IValueProvider _innerProvider;
    private readonly Type _propertyType;

    public DefaultValueProvider(IValueProvider innerProvider, Type propertyType)
    {
        _innerProvider = innerProvider;
        _propertyType = propertyType;
    }

    public object GetValue(object target)
    {
        // Set to the default value for the property type
        return GetDefaultValue(_propertyType);
    }

    public void SetValue(object target, object value)
    {
        _innerProvider.SetValue(target, value);
    }

    private object GetDefaultValue(Type type)
    {
        return type.IsValueType ? Activator.CreateInstance(type) : null;
    }
}



```


 is an exceptional project manager who consistently demonstrates foresight, ensuring that all necessary documents are prepared well in advance for the team's needs. His proactive approach and positive attitude set a great tone, fostering a collaborative and upbeat environment where each team member feels supported and valued. Phil's empathy and humility are evident in the way he interacts with others, never letting ego get in the way and always asking thoughtful questions in company-wide meetings to deepen his understanding. His leadership is a key factor in the team’s rock-star performance, making him an invaluable asset to both the team and the company.


AAAAA is an outstanding engineer and a key member of the development team, always proactive in taking on tasks and driving them to completion. His collaborative spirit ensures that projects move forward smoothly, whether he's working with internal team members or external partners. With a great personality for fostering effective teamwork, AAAAA consistently delivers results and makes cross-team coordination seamless. His sharp intellect and analytical thinking shine through in his problem-solving approach, making him an invaluable asset to any project he's involved in.


1
Azure Fundamentals certified with extensive LinkedIn training in DevOps and public cloud. Trained the Expanders team on Okta, becoming a Subject Matter Expert (SME). Planned a demo for the adoption of snapshot testing and provided internal training to the TDC team on BT Gateway, as well as to Expander team members on Okta.

2
Spent most of the time focused on new projects, but actively contributed to production support by assisting team members in achieving their goals.
3
Applied best practices and past experiences with ELK/AppInsight logging to enhance the logging architecture in BT Gateway, leading to improvements in its overall effectiveness.

4
I have completed all trainings on time with the goal of not just finishing, but also taking detailed notes, downloading attachments, and adding key points to my reading list and key takeaways to my to-do list for future application.

5
Participated in .NET upgrades, testing, and resolving vulnerabilities, contributing to maintaining and improving system security and performance.

6
Proactively worked on the backends of mobile projects ahead of time, reviewed and improved the architecture, and aligned the team on backend strategies. Became a BT API expert, and earlier, became an Okta API/integration expert, frequently consulted by colleagues like Sam, Shweta, and Michael.



















