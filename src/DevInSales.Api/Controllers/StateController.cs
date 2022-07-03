using DevInSales.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DevInSales.Api.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class StateController : ControllerBase
    {
        private readonly IStateService _stateService;

        public StateController(IStateService stateService)
        {
            _stateService = stateService;
        }

        /// <summary>
        /// Buscar estados.
        /// </summary>
        /// <remarks>
        /// Pesquisa opcional: name.
        /// <para>
        /// Exemplo de resposta:
        /// [
        ///   {
        ///     "id": 1,
        ///     "name": "Santa Catarina"
        ///     "initials": "SC"
        ///   }
        /// ]
        /// </para>
        /// </remarks>
        /// <returns>Lista de endereços</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">Pesquisa realizada com sucesso porém não retornou nenhum resultado</response>
        [HttpGet]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        public ActionResult GetAll(string? name)
        {
            var statesList = _stateService.GetAll(name);
            if (statesList == null || statesList.Count == 0)
                return NoContent();

            return Ok(statesList);
        }

        /// <summary>
        /// Buscar estados por id.
        /// </summary>
        /// <remarks>
        /// Exemplo de resposta:
        ///   {
        ///     "id": 1,
        ///     "name": "Santa Catarina"
        ///     "initials": "SC"
        ///   }
        /// </remarks>
        /// <returns>Lista de endereços</returns>
        /// <response code="200">Sucesso.</response>
        /// /// <response code="404">Not Found, estado não encontrado no stateId informado.</response>
        [HttpGet("{stateId}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult GetByStateId(int stateId)
        {
            var state = _stateService.GetById(stateId);

            if (state == null)
                return NotFound();

            return Ok(state);
        }
    }
}
