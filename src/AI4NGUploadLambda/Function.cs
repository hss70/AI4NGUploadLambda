using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Amazon.S3;
using Amazon.S3.Model;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]
namespace AI4NGUploadLambda;

public class Function
{
    private static readonly AmazonS3Client s3Client = new(GetRegion());

    public async Task<APIGatewayProxyResponse> FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
    {
        try
        {
            var bucketName = Environment.GetEnvironmentVariable("UPLOAD_BUCKET");
            var queryParams = request.QueryStringParameters ?? new Dictionary<string, string>();
            
            if (!queryParams.TryGetValue("fileName", out var fileName) || string.IsNullOrEmpty(fileName))
                return Error(400, "Missing 'fileName'");

            if (!queryParams.TryGetValue("saveLocation", out var saveLocation) || string.IsNullOrEmpty(saveLocation))
                return Error(400, "Missing 'saveLocation'");

            var username = GetUsernameFromJwt(GetJwtFromRequest(request));
            if (string.IsNullOrEmpty(username))
                return Error(400, "Username not found in JWT claims");

            // Generate sessionId from userId + sessionName
            var sessionId = GenerateSessionId(username, saveLocation);
            
            context.Logger.LogLine(JsonSerializer.Serialize(new {
                level = "INFO",
                message = "Upload request started",
                sessionId,
                sessionName = saveLocation,
                userId = username,
                fileName
            }));
            
            var key = $"{username}/{saveLocation}/{fileName}";
            var expiresIn = TimeSpan.FromHours(1);

            var presignRequest = new GetPreSignedUrlRequest
            {
                BucketName = bucketName,
                Key = key,
                Verb = HttpVerb.PUT,
                Expires = DateTime.UtcNow.Add(expiresIn)
            };
            
            // Validate presignRequest fields
            if (string.IsNullOrEmpty(presignRequest.BucketName))
                return Error(400, "BucketName is required for presigned URL");
            if (string.IsNullOrEmpty(presignRequest.Key))
                return Error(400, "Key is required for presigned URL");
            if (presignRequest.Expires <= DateTime.UtcNow)
                return Error(400, "Expiration time must be in the future");
            
            var url = s3Client.GetPreSignedURL(presignRequest);
            
            context.Logger.LogLine(JsonSerializer.Serialize(new {
                level = "INFO",
                message = "Presigned URL generated",
                sessionId,
                sessionName = saveLocation,
                userId = username,
                fileName,
                expiresIn = expiresIn.TotalMinutes
            }));

            return new APIGatewayProxyResponse
            {
                StatusCode = 200,
                Body = JsonSerializer.Serialize(new { 
                    presigned_url = url,
                    session_id = sessionId,
                    expires_in = (int)expiresIn.TotalSeconds
                }),
                Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" }
            };
        }
        catch (Exception ex)
        {
            context.Logger.LogLine(JsonSerializer.Serialize(new {
                level = "ERROR",
                message = "Upload request failed",
                error = ex.Message
            }));
            return Error(500, ex.Message);
        }
    }

    private static APIGatewayProxyResponse Error(int status, string message)
    {
        return new APIGatewayProxyResponse
        {
            StatusCode = status,
            Body = JsonSerializer.Serialize(new { error = message }),
            Headers = new Dictionary<string, string> { ["Content-Type"] = "application/json" }
        };
    }

    private string? GetUsernameFromJwt(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            Console.WriteLine("JWT token is null or empty.");
            return null;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            var usernameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "username" || c.Type == "cognito:username");

            return usernameClaim?.Value;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing JWT token: {ex.Message}");
            return null;
        }
    }
    private string GetJwtFromRequest(APIGatewayProxyRequest request)
    {
        if (request.Headers != null)
        {
            // Case-insensitive search for "authorization"
            var authHeaderKey = request.Headers.Keys
                .FirstOrDefault(k => k.Equals("Authorization", StringComparison.OrdinalIgnoreCase));

            if (authHeaderKey != null && request.Headers.TryGetValue(authHeaderKey, out var authHeader))
            {
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    return authHeader.Substring("Bearer ".Length);
                }
            }
        }
        return String.Empty;
    }

    private static int GenerateSessionId(string userId, string sessionName)
    {
        return Math.Abs((userId + sessionName).Aggregate(0, (a, b) => 
            ((a << 5) - a) + b));
    }
    
    private static Amazon.RegionEndpoint GetRegion()
    {
        // 1. Check environment variable
        var regionEnv = Environment.GetEnvironmentVariable("AWS_REGION");

        // 2. Use default region if none provided (for local dev)
        if (string.IsNullOrEmpty(regionEnv))
        {
            Console.WriteLine("No AWS_REGION set; using EUWest2 as default for local development");
            return Amazon.RegionEndpoint.GetBySystemName("eu-west-2");;
        }

        return Amazon.RegionEndpoint.GetBySystemName(regionEnv);
    }
    }
