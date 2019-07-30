using System.ComponentModel.DataAnnotations;

namespace Decent.PartialModels
{
    public class RegisterModel
    {
        public string Username { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }

        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}
