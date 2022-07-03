using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using DevInSales.Core.Data.Dtos;
using DevInSales.Core.Services;
using DevInSales.Identity.Configurations;

namespace DevInSales.Identity.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly Jwt _jwt;

        public IdentityService(SignInManager<IdentityUser> signInManager,
                               UserManager<IdentityUser> userManager,
                               IOptions<Jwt> jwt)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _jwt = jwt.Value;
        }

        public async Task<UserRegistrationResponse> UserRegistration(UserRegistrationRequest userRegistration)
        {
            var identityUser = new IdentityUser
            {
                UserName = userRegistration.Email,
                Email = userRegistration.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(identityUser, userRegistration.Password);
            if (result.Succeeded)
                await _userManager.SetLockoutEnabledAsync(identityUser, false);

            var userRegistrationResponse = new UserRegistrationResponse(result.Succeeded);
            if (!result.Succeeded && result.Errors.Count() > 0)
                userRegistrationResponse.AddErrors(result.Errors.Select(r => r.Description));

            return userRegistrationResponse;
        }

        public async Task<UserLoginResponse> Login(UserLoginRequest userLogin)
        {
            var result = await _signInManager.PasswordSignInAsync(userLogin.Email, userLogin.Password, false, true);
            if (result.Succeeded)
                return await GenerateCredenciais(userLogin.Email);

            var userLoginResponse = new UserLoginResponse();
            if (!result.Succeeded)
            {
                if (result.IsLockedOut)
                    userLoginResponse.AddError("Essa conta está bloqueada");
                else if (result.IsNotAllowed)
                    userLoginResponse.AddError("Essa conta não tem permissão para fazer login");
                else
                    userLoginResponse.AddError("Usuário ou senha estão incorretos");
            }

            return userLoginResponse;
        }

        private async Task<UserLoginResponse> GenerateCredenciais(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var tokenClaims = await GetClaimsAndRoles(user);

            var expirationDate = DateTime.Now.AddDays(_jwt.TokenExpiration);

            var token = GenerateToken(tokenClaims, expirationDate);

            return new UserLoginResponse
            (
                success: true,
                token: token,
                expirationDate: expirationDate
            );
        }

        private string GenerateToken(IEnumerable<Claim> claims, DateTime expirationDate)
        {
            var jwt = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                notBefore: DateTime.Now,
                expires: expirationDate,
                signingCredentials: _jwt.SigningCredentials);

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<IList<Claim>> GetClaimsAndRoles(IdentityUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, DateTime.Now.ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToString()));


            foreach (var role in roles)
                claims.Add(new Claim("role", role));

            return claims;
        }
    }
}
