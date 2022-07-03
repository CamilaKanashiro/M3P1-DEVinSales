
using DevInSales.Core.Data.Dtos;
using DevInSales.Core.Entities;
using DevInSales.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DevInSales.Api.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/sales/")]
    public class SalesController : ControllerBase
    {
        private readonly ISaleService _saleService;

        public SalesController(ISaleService saleService)
        {
            _saleService = saleService;
        }

        /// <summary>
        /// Busca uma venda com uma lista de produtos.
        /// </summary>
        ///<returns>Retorna uma venda com uma lista de produtos.</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="404">Not Found, quando o saleId não for encontrado.</response>
        [HttpGet("{saleId}")]
        public ActionResult<SaleResponse> GetSaleById(int saleId)
        {
            var sale = _saleService.GetSaleById(saleId);
            if (sale == null)
                return NotFound();

            return Ok(sale);
        }

        /// <summary>
        /// Busca as vendas de um determinado usuário.
        /// </summary>
        ///<returns>Retorna todas as vendas de um determinado usuário.</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">No Content, caso o usuário ainda não tenha cadastrado uma venda.</response>
        [HttpGet("/api/user/{userId}/sales")]
        public ActionResult<Sale> GetSalesBySellerId(int? userId)
        {
            var sales = _saleService.GetSaleBySellerId(userId);
            if (sales.Count == 0)
                return NoContent();
            return Ok(sales);
        }

        /// <summary>
        /// Busca as compras de um determinado usuário.
        /// </summary>
        ///<returns>Retorna todas as compras de um determinado usuário.</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">No Content, caso o usuário ainda não tenha cadastrado uma compra.</response>
        [HttpGet("/api/user/{userId}/buy")]
        public ActionResult<Sale> GetSalesByBuyerId(int? userId)
        {
            var sales = _saleService.GetSaleByBuyerId(userId);
            if (sales.Count == 0)
                return NoContent();
            return Ok(sales);
        }

        /// <summary>
        /// Cria uma nova venda para um usuário.
        /// </summary>
        ///<returns>Retorna o id da venda criada.</returns>
        /// <response code="201">Criado com sucesso.</response>
        /// <response code="400">Bad Request, quando não é enviado um buyerId.</response>
        /// <response code="404">Not Found, caso não exista um usuário com o Id enviado.</response>
        [HttpPost("/api/user/{userId}/sales")]
        [ProducesResponseType(StatusCodes.Status201Created)]

        public ActionResult<int> CreateSaleBySellerId(int userId, SaleBySellerRequest saleRequest)
        {
            try
            {
                Sale sale = saleRequest.ConvertToEntity(userId);
                var id = _saleService.CreateSaleByUserId(sale);
                return CreatedAtAction(nameof(GetSaleById), new { saleId = id }, id);
            }
            catch (ArgumentNullException ex)
            {
                return BadRequest(ex.ParamName);
            }
            catch (ArgumentException ex)
            {
                return NotFound(ex.Message);
            }
        }

        /// <summary>
        /// Altera o preço de um produto em determinada venda.
        /// </summary>
        ///<returns>Retorna No Content.</returns>
        /// <response code="204">Alterado com sucesso.</response>
        /// <response code="400">Bad Request, caso o preço digitado seja menor ou igual a zero.</response>
        /// <response code="404">Not Found, caso não exista uma venda com o saleId enviado ou um SaleProduct com o productId enviado</response>
        [HttpPatch("{saleId}/product/{productId}/price/{unitPrice}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]

        public ActionResult UpdateUnitPrice(int saleId, int productId, decimal unitPrice)
        {
            try
            {
                _saleService.UpdateUnitPrice(saleId, productId, unitPrice);
                return NoContent();
            }
            catch (ArgumentException ex)
            {
                return BadRequest();
            }
            catch (Exception ex)
            {
                return NotFound();
            }
        }

        /// <summary>
        /// Altera a quantidade de um produto em determinada venda.
        /// </summary>
        ///<returns>Retorna No Content.</returns>
        /// <response code="204">Alterado com sucesso.</response>
        /// <response code="400">Bad Request, caso a quantidade digitada seja menor ou igual a zero.</response>
        /// <response code="404">Not Found, caso não exista uma venda com o saleId enviado ou um SaleProduct com o productId enviado.</response>
        [HttpPatch("{saleId}/product/{productId}/amount/{amount}")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]

        public ActionResult UpdateAmount(int saleId, int productId, int amount)
        {

            try
            {

                _saleService.UpdateAmount(saleId, productId, amount);
                return NoContent();

            }
            catch (ArgumentException ex)
            {
                if (ex.ParamName.Equals("saleId") || ex.ParamName.Equals("productId"))
                    return NotFound(ex.Message);

                return BadRequest(ex.Message);
            }

        }
        /// <summary>
        /// Cria uma nova compra para um usuário.
        /// </summary>
        ///<returns>Retorna o id da compra criada.</returns>
        /// <response code="201">Criado com sucesso.</response>
        /// <response code="400">Bad Request, quando não enviado um sellerId.</response>
        /// <response code="404">Not Found, caso não exista um usuário com o Id enviado.</response>
        [HttpPost("/api/user/{userId}/buy")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        public ActionResult<int> CreateSaleByBuyerId(int userId, SaleByBuyerRequest saleRequest)
        {
            try
            {
                Sale sale = saleRequest.ConvertToEntity(userId);
                var id = _saleService.CreateSaleByUserId(sale);
                return CreatedAtAction(nameof(GetSaleById), new { saleId = id }, id);
            }
            catch (ArgumentNullException ex)
            {
                return BadRequest(ex.ParamName);
            }
            catch (ArgumentException ex)
            {
                return NotFound(ex.Message);
            }
        }
        /// <summary>
        /// Cria uma nova entrega para uma venda.
        /// </summary>
        ///<returns>Retorna o Id da entrega criada.</returns>
        /// <response code="201">Criado com sucesso.</response>
        /// <response code="400">Bad Request, caso não enviado um AddressId ou a data enviada seja anterior a data atual.</response>
        /// <response code="404">Not Found, caso não exista um saleId ou um addressId igual ao enviado.</response>

        [HttpPost("{saleId}/deliver")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        public ActionResult<int> CreateDeliveryForASale(int saleId, DeliveryRequest deliveryRequest)
        {
            try
            {
                if (deliveryRequest.AddressId <= 0)
                    return BadRequest("AddressId não pode ser menor ou igual a zero e nulo.");

                if (deliveryRequest.DeliveryForecast == DateTime.MinValue)
                    deliveryRequest.DeliveryForecast = DateTime.Now.AddDays(7).ToUniversalTime();

                if (deliveryRequest.DeliveryForecast < DateTime.Now.ToUniversalTime())
                    return BadRequest("Data e hor�rio n�o podem ser anterior ao atual.");

                Delivery delivery = deliveryRequest.ConvertToEntity(saleId);

                int id = _saleService.CreateDeliveryForASale(delivery);

                return CreatedAtAction(nameof(GetDeliveryById), new { deliveryId = id }, id);
            }
            catch (ArgumentException ex)
            {

                if (ex.ParamName.Equals("saleId") || ex.ParamName.Equals("AddressId"))
                    return NotFound(ex.Message);


                return BadRequest();

            }

        }

        //Endpoint criado apenas para servir como caminho do POST {saleId}/deliver
        [ApiExplorerSettings(IgnoreApi = true)]
        [HttpGet("/api/delivery/{deliveryId}")]
        public ActionResult<Delivery> GetDeliveryById(int deliveryId)
        {
            Delivery delivery = _saleService.GetDeliveryById(deliveryId);
            if (delivery == null)
                return NoContent();
            return Ok(delivery);
        }

    }
}