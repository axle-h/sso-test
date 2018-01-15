using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace Sso.ActiveDirectory.Services
{
    public class AccountService : IAccountService
    {
        private static readonly string WindowsAuthenticationSchemeName = Microsoft.AspNetCore.Server.IISIntegration.IISDefaults.AuthenticationScheme;
        private readonly IAuthenticationSchemeProvider _schemeProvider;

        public AccountService(IAuthenticationSchemeProvider schemeProvider)
        {
            _schemeProvider = schemeProvider;
        }

        public async Task<string> GetExternalProviderNameAsync()
        {
            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var provider = schemes.FirstOrDefault(x => x.Name.Equals(WindowsAuthenticationSchemeName, StringComparison.OrdinalIgnoreCase));
            if (provider == null)
            {
                throw new InvalidOperationException("Windows authentication scheme is not configured, are we running on IIS?");
            }

            return provider.Name;
        }
    }
}
