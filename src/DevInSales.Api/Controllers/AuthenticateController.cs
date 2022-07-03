using DevInSales.Core.Data.Dtos;
using DevInSales.Core.Services;
using Microsoft.AspNetCore.Mvc;


namespace DevInSales.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private IIdentityService _identityService;

        public AuthenticateController(IIdentityService identityService) =>
            _identityService = identityService;

        [HttpPost("cadastro")]
        public async Task<ActionResult<UserRegistrationResponse>> Register(UserRegistrationRequest userRegistration)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var resultado = await _identityService.UserRegistration(userRegistration);
            if (resultado.Success)
                return Ok(resultado);
            else if (resultado.Errors.Count > 0)
                return BadRequest(resultado);

            return StatusCode(StatusCodes.Status500InternalServerError);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserRegistrationResponse>> Login(UserLoginRequest userLogin)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            var result = await _identityService.Login(userLogin);
            if (result.Success)
                return Ok(result);

            return Unauthorized(result);
        }
    }
}
