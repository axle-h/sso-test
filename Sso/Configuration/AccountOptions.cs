using System;

namespace Sso.Configuration
{
    public class AccountOptions
    {
        public bool AllowRememberLogin { get; set; }

        public TimeSpan RememberMeLoginDuration { get; set; }

        public bool ShowLogoutPrompt { get; set; }

        public bool AutomaticRedirectAfterSignOut { get; set; }
        
        public string InvalidCredentialsErrorMessage { get; set; }
    }
}
