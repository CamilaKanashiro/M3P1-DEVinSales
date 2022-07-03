using DevInSales.Api.Dtos;
using DevInSales.Core.Entities;
using DevInSales.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DevInSales.Api.Controllers
{
    [Authorize]
    [ApiController]
    public class CityController : ControllerBase
    {
        private readonly IStateService _stateService;
        private readonly ICityService _cityService;

        public CityController(IStateService stateService, ICityService cityService)
        {
            _stateService = stateService;
            _cityService = cityService;
        }

        /// <summary>
        /// Buscar cidades.
        /// </summary>
        /// <remarks>
        /// Pesquisa opcional: name.
        /// <para>
        /// Exemplo de resposta:
        /// [
        ///   {
        ///     "id": 1,
        ///     "name": "Jaraguá do Sul"
        ///     },
        ///     "state": {
        ///         "id": 1,
        ///         "name": "Santa Catarina"
        ///         "initials": "SC"
        ///   }
        /// ]
        /// </para>
        /// </remarks>
        /// <returns>Lista de endereços</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">Pesquisa realizada com sucesso porém não retornou nenhum resultado</response>
        /// <response code="404">Not Found, estado não encontrado no stateId informado.</response>
        [HttpGet("/api/State/{stateId}/city")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult GetCityByStateId(int stateId, string? name)
        {
            var state = _stateService.GetById(stateId);
            if (state == null)
                return NotFound();

            var citiesList = _cityService.GetAll(stateId, name);
            if (citiesList == null || citiesList.Count == 0)
                return NoContent();

            return Ok(citiesList);
        }

        /// <summary>
        /// Buscar cidade por id.
        /// </summary>
        /// <remarks>
        /// Exemplo de resposta:
        ///  {
        ///    "id": 1,
        ///    "name": "Jaraguá do Sul"
        ///    },
        ///    "state": {
        ///        "id": 1,
        ///        "name": "Santa Catarina"
        ///        "initials": "SC"
        ///  }
        /// </remarks>
        /// <returns>Lista de endereços</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="400">Bad Request, stateId informado é diferente do stateId da cidade cadastrada no banco de dados.</response>
        /// <response code="404">Not Found, estado não encontrado no stateId informado.</response>
        /// <response code="404">Not Found, cidade não encontrada no cityId informado.</response>
        [HttpGet("/api/State/{stateId}/city/{cityId}")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult GetCityById(int stateId, int cityId)
        {
            var state = _stateService.GetById(stateId);
            if (state == null)
                return NotFound();

            var city = _cityService.GetById(cityId);
            if (city == null)
                return NotFound();

            if (state.Id != city.State.Id)
                return BadRequest();

            return Ok(city);
        }

        /// <summary>
        /// Cadastrar uma cidade.
        /// </summary>
        /// <remarks>
        /// Exemplo:
        /// {
        ///    "name": "Jaraguá do Sul"
        /// }
        /// </remarks>
        /// <param name="model">Dados da cidade</param>
        /// <returns>Id da cidade criada</returns>
        /// <response code="201">Cadastrado com sucesso.</response>
        /// <response code="400">Bad Request, cidade já cadastrada no banco de dados.</response>
        /// <response code="404">Not Found, estado não encontrado no stateId informado.</response>
        [HttpPost("/api/State/{stateId}/city")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public ActionResult AddCity(int stateId, AddCity model)
        {
            var state = _stateService.GetById(stateId);
            if (state == null)
                return NotFound();

            var city = _cityService.GetAll(stateId, model.Name);
            if (city != null && city.Count > 0)
                return BadRequest();

            var newCity = new City(stateId, model.Name);
            _cityService.Add(newCity);

            return CreatedAtAction(
                nameof(GetCityById),
                new { stateId, cityId = newCity.Id },
                newCity.Id
            );
        }
    }
}
