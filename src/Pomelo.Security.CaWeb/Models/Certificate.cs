using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Pomelo.Security.CaWeb.Models
{
    public enum CertificateType
    { 
        RootCA,
        IntermediateCA,
        Client,
        Server,
        CodeSigning
    }

    public class Certificate
    {
        public Guid Id { get; set; }

        [ForeignKey(nameof(Certificate))]
        public Guid? ParentId { get; set; }

        public virtual Certificate Parent { get; set; }

        public DateTime IssuedAt { get; set; } = DateTime.UtcNow;

        [ForeignKey(nameof(Owner))]
        public string Username { get; set; }

        public virtual User Owner { get; set; }

        public CertificateType Type { get; set; }

        [JsonIgnore]
        public byte[] KeyFile { get; set; } // Maybe stored

        [JsonIgnore]
        public byte[] CrtFile { get; set; }

        public virtual ICollection<Certificate> Children { get; set; } = new List<Certificate>();
    }
}
