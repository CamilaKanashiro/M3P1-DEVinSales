
namespace DevInSales.Core.Data.Dtos
{
    public class UserRegistrationResponse
    {
        public bool Success { get; private set; }
        public List<string> Errors { get; private set; }

        public UserRegistrationResponse() =>
            Errors = new List<string>();

        public UserRegistrationResponse(bool success = true) : this() =>
            Success = success;

        public void AddErrors(IEnumerable<string> errors) =>
            Errors.AddRange(errors);
    }
}
