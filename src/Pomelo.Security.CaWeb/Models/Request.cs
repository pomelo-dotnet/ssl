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

        public DateTime? ValidatedAt { get; set; }

        public string ValidationMessage { get; set; }

        public string CsrContent { get; set; }
    }
}
