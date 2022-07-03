using DevInSales.Api.Dtos;
using DevInSales.Core.Entities;
using DevInSales.Core.Interfaces;
using DevInSales.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DevInSales.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductController : ControllerBase
    {
        private readonly IProductService _productService;

        public ProductController(IProductService productService)
        {
            _productService = productService;
        }

        /// <summary>
        /// Buscar produtos por id.
        /// </summary>
        /// <remarks>
        /// Exemplo:
        ///   {
        ///     "id": 1,
        ///     "name": "Produto 1",
        ///     "description": "Descrição do produto 1",
        ///     "price": 100.00,
        ///   }
        /// </remarks>
        /// <returns></returns>
        /// <response code="204">A atualização teve sucesso.</response>
        /// <response code="404">Not Found. O Produto solicitado não existe.</response>
        [Authorize]
        [HttpGet("{id}")]
        public ActionResult<Product> ObterProdutoPorId(int id)
        {
            var produto = _productService.ObterProductPorId(id);
            if (produto == null)
                return NotFound();
            return Ok(produto);
        }


        /// <summary>
        ///  Modificar produto.
        /// </summary>
        /// <remarks>
        /// Exemplo:
        ///   {
        ///     "name": "Produto 2",
        ///     "description": "Descrição do produto 2",
        ///     "price": 105.00,
        ///   }
        /// </remarks>
        /// <returns></returns>
        /// <response code="200">A atualização teve sucesso.</response>
        /// <response code="204">No Content, caso não encontrado nenhum resultado.</response>
        /// <response code="400">Bad Request, não é possível deletar este endereço pois ele está na lista de entrega</response>


        [HttpPut("{id}")]
        public ActionResult AtualizarProduto(AddProduct model, int id)
        {
            var productOld = _productService.ObterProductPorId(id);

            if (model == null)
                return NotFound();
            if (!ModelState.IsValid || model.Name.ToLower() == "string")
                return BadRequest("O objeto tem que ser construido com um nome e nome tem que ser diferente de string");
            if (_productService.ProdutoExiste(model.Name))
                return BadRequest("esse nome já existe na base de dados");


            productOld.AtualizarDados(model.Name, model.SuggestedPrice);

            _productService.Atualizar();

            return NoContent();
        }


        /// <summary>
        ///  Deleta um produto pelo id.
        /// </summary>
        /// <response code="204">No Content, caso não encontrado nenhum resultado.</response>
        /// <response code="404">Not Found, endereço não encontrado.</response>
        /// <response code="400">Bad Request, stateId informado é diferente do stateId da cidade cadastrada no banco de dados.</response>
        /// <response code="500"> Internal Server Error, erro interno do servidor. </response>


        [HttpDelete("{id}")]
        public ActionResult Delete(int id)
        {
            try
            {
                _productService.Delete(id);
                return NoContent();
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("não existe"))
                    return NotFound();
                if (ex.HResult == -2146233088)
                    return BadRequest("O produto especificado não pode ser excluido, porque já está atrelado a outra tabela!");

                return StatusCode(StatusCodes.Status500InternalServerError, new { Mensagem = ex.Message });
            }

        }

        /// <summary>
        /// Busca todos os produtos.
        /// </summary>
        /// <remarks>
        /// Exemplo de resposta:
        ///  {
        ///    "name": "produto 1"
        ///    "suggestedPrice": 100.00
        ///  }
        /// </remarks>
        /// <returns>Lista de produtos</returns>
        /// <response code="200">Sucesso.</response>
        /// <response code="204">No Content, caso não encontrado nenhum resultado.</response>
        /// <response code="400">Bad Request, stateId informado é diferente do stateId da cidade cadastrada no banco de dados.</response>

        [HttpGet]
        public ActionResult<List<Product>> GetAll(string? name, decimal? priceMin, decimal? priceMax)
        {
            try
            {
                if (priceMax < priceMin)
                    return BadRequest("O preço mínimo não pode ser maior que o preço máximo");

                var ProductList = _productService.ObterProdutos(name, priceMin, priceMax);
                if (ProductList.Count == 0 || ProductList == null)
                    return NoContent();
                return Ok(ProductList);
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { Mensagem = ex.Message });
            }
        }


        /// <summary>
        /// Cadastrar um produto.
        /// </summary>
        /// <remarks>
        /// Exemplo:
        /// {
        ///    "name": "Produto 1",
        ///    "suggestedPrice": 100.00
        /// }
        /// </remarks>
        /// <returns> product id </returns>
        /// <response code="201">Cadastrado com sucesso.</response>
        /// <response code="400">Bad Request Esse produto já existe na base de dados</response>
        [HttpPost]
        public ActionResult PostProduct(AddProduct model)
        {
            var product = new Product(model.Name, model.SuggestedPrice);

            if (_productService.ProdutoExiste(product.Name))
                return BadRequest("Esse produto já existe na base de dados");

            var ProductId = _productService.CreateNewProduct(product);

            return CreatedAtAction(nameof(ObterProdutoPorId), new { id = ProductId }, ProductId);
        }
    }
}