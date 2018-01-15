using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Sso.ActiveDirectory.Attributes;
using Sso.ActiveDirectory.Configuration;
using Sso.ActiveDirectory.Services;

namespace Sso.ActiveDirectory.Controllers
{
    [SecurityHeaders]
    public class AccountController : Controller
    {
        private readonly IAccountService _accountService;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IEventService _events;
        private readonly IOptions<AccountOptions> _options;

        public AccountController(IAccountService accountService, IIdentityServerInteractionService interaction, IEventService events, IOptions<AccountOptions> options)
        {
            _accountService = accountService;
            _interaction = interaction;
            _events = events;
            _options = options;
        }

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            var provider = await _accountService.GetExternalProviderNameAsync();
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(ExternalLoginCallback)),
                Items =
                {
                    {"returnUrl", returnUrl}
                }
            };

            // see if windows auth has already been requested and succeeded
            var result = await HttpContext.AuthenticateAsync(provider);
            if (result?.Principal is WindowsPrincipal wp)
            {
                props.Items.Add("scheme", provider);

                var id = new ClaimsIdentity(provider);
                id.AddClaim(new Claim(JwtClaimTypes.Subject, wp.Identity.Name));
                id.AddClaim(new Claim(JwtClaimTypes.Name, wp.Identity.Name));

                // add the groups as claims -- be careful if the number of groups is too large
                if (_options.Value.IncludeWindowsGroups)
                {
                    var wi = wp.Identity as WindowsIdentity;
                    var groups = wi.Groups.Translate(typeof(NTAccount));
                    var roles = groups.Select(x => new Claim(JwtClaimTypes.Role, x.Value));
                    id.AddClaims(roles);
                }

                await HttpContext.SignInAsync(
                    IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme,
                    new ClaimsPrincipal(id),
                    props);
                return Redirect(props.RedirectUri);
            }

            // challenge/trigger windows auth
            return Challenge(provider);
        }

        /// <summary>
        /// Post processing of external authentication
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> ExternalLoginCallback()
        {
            // read external identity from the temporary cookie
            var result = await HttpContext.AuthenticateAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result?.Succeeded != true)
            {
                throw new Exception("External authentication error");
            }

            // retrieve claims of the external user
            var externalUser = result.Principal;
            var claims = externalUser.Claims.ToList();
            var provider = result.Properties.Items["scheme"];

            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.Subject)
                              ?? claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)
                              ?? throw new InvalidOperationException("Unknown user ID for external provider: " + provider);
            
            // remove the user id claim from the claims collection and move to the userId property
            // also set the name of the external authentication provider
            claims.Remove(userIdClaim);
            var userId = userIdClaim.Value;
            
            var additionalClaims = new List<Claim>();

            // if the external system sent a session id claim, copy it over
            // so we can use it for single sign-out
            var sid = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
            if (sid != null)
            {
                additionalClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
            }

            // if the external provider issued an id_token, we'll keep it for signout
            AuthenticationProperties props = null;
            var id_token = result.Properties.GetTokenValue("id_token");
            if (id_token != null)
            {
                props = new AuthenticationProperties();
                props.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = id_token } });
            }

            // issue authentication cookie for user
            var (subjectId, username) = GetUser(claims);
            await _events.RaiseAsync(new UserLoginSuccessEvent(provider, userId, subjectId, username));
            await HttpContext.SignInAsync(subjectId, username, provider, props, additionalClaims.ToArray());

            // delete temporary cookie used during external authentication
            await HttpContext.SignOutAsync(IdentityServer4.IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // validate return URL and redirect back to authorization endpoint or a local page
            var returnUrl = result.Properties.Items["returnUrl"];
            if (_interaction.IsValidReturnUrl(returnUrl) || Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return Redirect("~/");
        }

        private static (string subjectId, string username) GetUser(IEnumerable<Claim> claims)
        {
            // create a list of claims that we want to transfer into our store
            var filtered = claims.Select(claim =>
            {
                // if the external system sends a display name - translate that to the standard OIDC name claim
                if (claim.Type == ClaimTypes.Name)
                {
                    return new Claim(JwtClaimTypes.Name, claim.Value);
                }

                // if the JWT handler has an outbound mapping to an OIDC claim use that
                if (JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap.ContainsKey(claim.Type))
                {
                    return new Claim(JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap[claim.Type], claim.Value);
                }

                // copy the claim as-is
                return claim;
            }).ToList();

            // if no display name was provided, try to construct by first and/or last name
            if (filtered.All(x => x.Type != JwtClaimTypes.Name) && TryGetFullNameFromComponents(filtered, out var fullName))
            {
                filtered.Add(new Claim(JwtClaimTypes.Name, fullName));
            }

            // create a new unique subject id
            var subjectId = CryptoRandom.CreateUniqueId();

            // check if a display name is available, otherwise fallback to subject id
            var name = filtered.FirstOrDefault(c => c.Type == JwtClaimTypes.Name)?.Value ?? subjectId;

            return (subjectId, name);
        }

        private static bool TryGetFullNameFromComponents(ICollection<Claim> claims, out string fullName)
        {
            var first = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.GivenName)?.Value;
            var last = claims.FirstOrDefault(x => x.Type == JwtClaimTypes.FamilyName)?.Value;
            if (!string.IsNullOrEmpty(first) && !string.IsNullOrEmpty(last))
            {
                fullName = first + " " + last;
                return true;
            }

            if (!string.IsNullOrEmpty(first))
            {
                fullName = first;
                return true;
            }

            if (!string.IsNullOrEmpty(last))
            {
                fullName = last;
                return true;
            }

            fullName = null;
            return false;
        }
    }
}
