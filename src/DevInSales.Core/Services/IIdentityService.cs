using DevInSales.Core.Data.Dtos;

namespace DevInSales.Core.Services
{
    public interface IIdentityService
    {
        Task<UserRegistrationResponse> UserRegistration(UserRegistrationRequest UserRegistration);

        Task<UserLoginResponse> Login(UserLoginRequest userLogin);
    }
}
