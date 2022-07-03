using System.ComponentModel.DataAnnotations;

namespace DevInSales.Core.Data.Dtos;

public class UserRegistrationRequest
{
    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [EmailAddress(ErrorMessage = "O campo {0} é inválido")]
    public string Email { get; set; }

    [Required(ErrorMessage = "O campo {0} é obrigatório")]
    [StringLength(20, ErrorMessage = "O campo {0} deve ter entre {2} e {1} caracteres", MinimumLength = 6)]
    public string Password { get; set; }

    [Compare(nameof(Password), ErrorMessage = "As senhas devem ser iguais")]
    public string PasswordConfirmation { get; set; }
}
