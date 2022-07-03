using Microsoft.AspNetCore.Mvc;
using DevInSales.Core.Entities;
using DevInSales.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;

namespace DevInSales.Api.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/deliver")]
    public class DeliveryController : ControllerBase
    {
        private readonly IDeliveryService _deliveryService;

        public DeliveryController(IDeliveryService deliveryService)
        {
            _deliveryService = deliveryService;
        }
        /// <summary>
        /// Busca uma lista de entregas.
        /// </summary>
        ///<returns>Retorna uma lista de entregas à depender do parâmetro enviado (SaleId ou IdAdress).</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">No Content, caso não encontrado nenhum resultado.</response>
        [HttpGet]
        public ActionResult<Delivery> GetDelivery(int? idAddress, int? saleId)
        {
            var delivery = _deliveryService.GetBy(idAddress, saleId);
            if (delivery.Count == 0)
                return NoContent();
            return Ok(delivery);
        }
    }
}