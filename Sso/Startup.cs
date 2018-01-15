using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Sso.Configuration;
using Sso.Services;

namespace Sso
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddOptions();
            var authSection = _configuration.GetSection("auth");
            services.Configure<AccountOptions>(authSection);

            services.AddLogging(c => c.AddConsole().AddDebug());

            services.AddTransient<IAccountService, AccountService>();

            services.AddIdentityServer()
                .AddDeveloperSigningCredential()
                .AddInMemoryPersistedGrants()
                .AddInMemoryIdentityResources(GetIdentityResources())
                .AddInMemoryApiResources(GetApiResources())
                .AddInMemoryClients(GetClients())
                .AddTestUsers(GetUsers());

            services
                .AddAuthentication()
                .AddOpenIdConnect("oidc", "Windows", options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                    options.Authority = "http://local.windows-sso.com/"; // TODO: config
                    options.RequireHttpsMetadata = false; // TODO: throw if not in development mode
                    options.ClientId = "implicit";
                    options.SaveTokens = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        RoleClaimType = "role"
                    };
                    options.Events = new OpenIdConnectEvents
                    {
                        OnRemoteFailure = context =>
                        {
                            context.Response.Redirect("/");
                            context.HandleResponse();

                            return Task.FromResult(0);
                        }
                    };
                });

            services.AddMvc();
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();
            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();
        }
        
        private static IEnumerable<IdentityResource> GetIdentityResources()
        {
            yield return new IdentityResources.OpenId();
            yield return new IdentityResources.Profile();
            yield return new IdentityResources.Email();
            yield return new IdentityResources.Phone();
        }

        private static IEnumerable<ApiResource> GetApiResources()
        {
            yield return new ApiResource("api1", "My API");
        }

        // clients want to access resources (aka scopes)
        private static IEnumerable<Client> GetClients()
        {
            // OpenID Connect hybrid flow and client credentials client (MVC)
            yield return new Client
            {
                ClientId = "mvc",
                ClientName = "MVC Client",
                AllowedGrantTypes = GrantTypes.Implicit,
                RedirectUris = {"http://localhost:5002/signin-oidc"},
                PostLogoutRedirectUris = {"http://localhost:5002/signout-callback-oidc"},
                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile
                },
                RequireConsent = false
            };
        }

        private static List<TestUser> GetUsers()
        {
            return new List<TestUser>
                   {
                       new TestUser
                       {
                           SubjectId = "1",
                           Username = "alice",
                           Password = "password",

                           Claims = new List<Claim>
                                    {
                                        new Claim("name", "Alice"),
                                        new Claim("website", "https://alice.com")
                                    }
                       },
                       new TestUser
                       {
                           SubjectId = "2",
                           Username = "bob",
                           Password = "password",

                           Claims = new List<Claim>
                                    {
                                        new Claim("name", "Bob"),
                                        new Claim("website", "https://bob.com")
                                    }
                       }
                   };
        }
    }
}
