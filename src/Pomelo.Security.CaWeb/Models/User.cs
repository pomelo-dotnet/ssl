using System.ComponentModel.DataAnnotations;

namespace Pomelo.Security.CaWeb.Models
{
    public enum UserRole
    {
        User,
        Admin,
        Root
    }

    public class User
    {
        [MaxLength(256)]
        public string Username { get; set; }

        [MaxLength(256)]
        public string Email { get; set; }

        [MaxLength(256)]
        public string DisplayName { get; set; }

        public UserRole Role { get; set; }
    }
}
