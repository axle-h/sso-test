using System.Threading.Tasks;
using Sso.Models.Account;

namespace Sso.Services
{
    public interface IAccountService
    {
        Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl);
        Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model);
        Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId);
        Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId);
    }
}