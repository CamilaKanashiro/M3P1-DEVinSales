using Microsoft.IdentityModel.Tokens;

namespace DevInSales.Identity.Configurations
{
    public class Jwt
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
        public int TokenExpiration { get; set; }
    }
}
