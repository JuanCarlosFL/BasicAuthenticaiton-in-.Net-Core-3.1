# BasicAuthenticaiton-in-.Net-Core-3.1

In this type of authentication we have to pass the user credentials in the request header, if we don't pass it then the server returns 401 (unathorized) status code indicating the server supports Basic Authentication.

- We have to create a class which inherit from AuthenticationHandler and overrides the HandleAuthenticateAsync method. Create the class inside Helpers folder

```C#
public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IUserService _userService;

        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IUserService userService)
            : base(options, logger, encoder, clock)
        {
            _userService = userService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // skip authentication if endpoint has [AllowAnonymous] attribute
            var endpoint = Context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null)
                return AuthenticateResult.NoResult();

            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Missing Authorization Header");

            User user = null;
            try
            {
                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                var username = credentials[0];
                var password = credentials[1];
                user = await _userService.Authenticate(username, password);
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }

            if (user == null)
                return AuthenticateResult.Fail("Invalid Username or Password");

            var claims = new[] {
                new Claim(ClaimTypes.Name, user.Username),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
```

In this file we can see that we are using an interface: IUserService
We can create de Services folder and inside we create the UserService.cs file

```C#
public class UserService : IUserService
{
    private readonly IConfiguration _configuration;

    public UserService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<User> Authenticate(string username, string password)
    {
        var user = await Task.Run(() => _configuration["user"] == username && _configuration["password"] == password);

        if (user)
            return new User() { Password = null, Username = username }; // authentication successful so return user details without password

        return null;
    }
}
```

With IConfiguration interface we can access to appsetings properties and we can store the username and password

```JSON
"user": "username",
"password": "password",
```

For that implementation we need the User.cs model, inside Entities folder:

```C#
public class User
    {
        public string Password { get; set; }

        public string Username { get; set; }
    }
```


In the Startup.cs need to add the authenciation middleware before the authorization

```C#
app.UseAuthentication();
app.UseAuthorization();
```

And in the ConfigureServices method

```C#
// configure basic authentication
services.AddAuthentication("BasicAuthentication")
    .AddScheme<AuthenticationSchemeOptions, BasicAuthenticationHandler>("BasicAuthentication", null);

// configure DI for application services
services.AddScoped<IUserService, UserService>();
```

In each controller method you want to protect

```C#
using Microsoft.AspNetCore.Authorization;

[HttpGet]
[Authorize]
```

For C# call with HttpClient

```C#
var client = new HttpClient();

client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
AuthenticationSchemes.Basic.ToString(),
    Convert.ToBase64String(Encoding.ASCII.GetBytes($"{Constants.SERVICEUSERNAME}:{Constants.SERVICEPASSWORD}"))
);

var response = client.GetAsync(url).Result;

var result = response.Content.ReadAsStringAsync().Result;

return Json(result, JsonRequestBehavior.AllowGet);
```



Example for add headers to XMLHttpRequest

```JS
let formData = new FormData();
...
xhr.open('POST', uri, true);
xhr.setRequestHeader("Authorization", "Basic username:passwordInBase64");
xhr.send(formData);
```

Example for add headers to Fetch call

```JS
await fetch(url,
    {
        headers: new Headers({
            'Authorization': 'Basic username:passwordInBase64',
            'Content-Type': 'application/json; charset=utf-8'
        }),
        method: 'POST',
        body: JSON.stringify(xxxx)
    })
    .catch(error => console.error(error));
```
