using System.Threading.Tasks;

namespace Sso.ActiveDirectory.Services
{
    public interface IAccountService
    {
        Task<string> GetExternalProviderNameAsync();
    }
}