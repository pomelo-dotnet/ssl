namespace Pomelo.Security.CaWeb.Models.ViewModels
{
    public class PostCertificateRequest
    {
        public CertificateType Type { get; set; }

        public RequestMode Mode { get; set; }

        public string RequestMessage { get; set; }

        public string CsrContent { get; set; }

        public string CommonName { get; set; }

        public string Organization { get; set; }

        public string OrganizationUnit { get; set; }

        public string Country { get; set; }

        public string Province { get; set; }

        public string City { get; set; }

        public string Email { get; set; }

        public string Dns { get; set; }
    }
}
