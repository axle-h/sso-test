using System.Collections.Generic;
using System.Security.Claims;
using IdentityServer4;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

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
            services.AddLogging(c => c.AddConsole().AddDebug());
            
            services.AddIdentityServer()
                    .AddDeveloperSigningCredential()
                    .AddInMemoryPersistedGrants()
                    .AddInMemoryIdentityResources(GetIdentityResources())
                    .AddInMemoryApiResources(GetApiResources())
                    .AddInMemoryClients(GetClients())
                    .AddTestUsers(GetUsers());

            services.AddAuthentication()
                    .AddGoogle("Google", options =>
                                         {
                                             options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                                             options.ClientId = "434483408261-55tc8n0cs4ff1fe21ea8df2o443v2iuc.apps.googleusercontent.com";
                                             options.ClientSecret = "3gcoTrEDPPJ0ukn_aYYT6PWo";
                                         })
                    .AddOpenIdConnect("oidc", "OpenID Connect", options =>
                                                                {
                                                                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                                                                    options.SignOutScheme = IdentityServerConstants.SignoutScheme;

                                                                    options.Authority = "https://demo.identityserver.io/";
                                                                    options.ClientId = "implicit";

                                                                    options.TokenValidationParameters = new TokenValidationParameters
                                                                                                        {
                                                                                                            NameClaimType = "name",
                                                                                                            RoleClaimType = "role"
                                                                                                        };
                                                                });

            services.AddMvc();
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }

            app.UseStaticFiles();
            app.UseIdentityServer();
            app.UseMvcWithDefaultRoute();
        }

        // scopes define the resources in your system
        private static IEnumerable<IdentityResource> GetIdentityResources()
        {
            yield return new IdentityResources.OpenId();
            yield return new IdentityResources.Profile();
        }

        private static IEnumerable<ApiResource> GetApiResources()
        {
            yield return new ApiResource("api1", "My API");
        }

        // clients want to access resources (aka scopes)
        private static IEnumerable<Client> GetClients()
        {
            // client credentials client
            yield return new Client
                         {
                             ClientId = "client",
                             AllowedGrantTypes = GrantTypes.ClientCredentials,

                             ClientSecrets =
                             {
                                 new Secret("secret".Sha256())
                             },
                             AllowedScopes = { "api1" }
                         };

            // resource owner password grant client
            yield return new Client
                         {
                             ClientId = "ro.client",
                             AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,

                             ClientSecrets =
                             {
                                 new Secret("secret".Sha256())
                             },
                             AllowedScopes = { "api1" }
                         };

            // OpenID Connect hybrid flow and client credentials client (MVC)
            yield return new Client
                         {
                             ClientId = "mvc",
                             ClientName = "MVC Client",
                             AllowedGrantTypes = GrantTypes.Implicit,

                             RedirectUris = { "http://localhost:5002/signin-oidc" },
                             PostLogoutRedirectUris = { "http://localhost:5002/signout-callback-oidc" },

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
