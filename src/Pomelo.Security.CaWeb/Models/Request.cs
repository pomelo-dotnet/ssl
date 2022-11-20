using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Pomelo.Security.CaWeb.Models
{
    public enum RequestStatus
    {
        Pending,
        Approved,
        Rejected
    }

    public enum RequestMode
    {
        FromCsr,
        FromInfo
    }

    public class Request
    {
        public Guid Id { get; set; }

        public CertificateType Type { get; set; }

        public RequestStatus Status { get; set; }

        [MaxLength(256)]
        [ForeignKey(nameof(User))]

        public string Username { get; set; }

        public virtual User User { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? HandledAt { get; set; }

        public string RequestMessage { get; set; }

        public string ValidationMessage { get; set; }

        public string Dns { get; set; }

        [MaxLength(512)]
        public string CommonName { get; set; }

        public string CsrContent { get; set; }

        public string KeyContent { get; set; }

        [MaxLength(32)]
        public string KeyPassword { get; set; }

        [ForeignKey(nameof(Certificate))]
        public Guid? CertificateId { get; set; }

        public virtual Certificate Certificate { get; set; }
    }
}
