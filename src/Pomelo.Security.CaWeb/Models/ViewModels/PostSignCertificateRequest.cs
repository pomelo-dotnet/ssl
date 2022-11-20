using System;

namespace Pomelo.Security.CaWeb.Models.ViewModels
{
    public class PostSignCertificateRequest
    {
        public string Algorithm { get; set; } = "sha384";

        public int Days { get; set; }

        public Guid? CaCertificateId { get; set; }

        public string[] CrlUrls { get; set; }
    }
}
