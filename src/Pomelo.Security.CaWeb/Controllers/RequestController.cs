using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Pomelo.EntityFrameworkCore.Lolita;
using Pomelo.Security.CaWeb.Models;
using Pomelo.Security.CaWeb.Models.ViewModels;
using Pomelo.Security.Ssl;

namespace Pomelo.Security.CaWeb.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class RequestController : ControllerBase
    {
        [HttpGet]
        public async ValueTask<ApiPagedResult<Request>> GetPendingRequests(
            [FromServices] CaContext db,
            [FromQuery] RequestStatus? status = null,
            [FromQuery] CertificateType? type = null,
            [FromQuery] DateTime? from = null,
            [FromQuery] DateTime? to = null,
            [FromQuery] bool? isHandled = null,
            [FromQuery] string commonName = null,
            [FromQuery] string username = null,
            CancellationToken cancellationToken = default)
        {
            IQueryable<Request> requests = db.Requests;

            if (status.HasValue)
            {
                requests = requests.Where(x => x.Status == status.Value);
            }

            if (type.HasValue)
            {
                requests = requests.Where(x => x.Type == type.Value);
            }

            if (from.HasValue)
            {
                requests = requests.Where(x => x.CreatedAt >= from.Value);
            }

            if (to.HasValue)
            {
                requests = requests.Where(x => x.CreatedAt < to.Value);
            }

            if (isHandled.HasValue)
            {
                requests = requests.Where(x => x.HandledAt.HasValue);
            }

            if (!string.IsNullOrWhiteSpace(commonName))
            {
                requests = requests.Where(x => x.CommonName.Contains(commonName));
            }

            if (!string.IsNullOrWhiteSpace(username))
            {
                requests = requests.Where(x => x.Username == username);
            }

            return await PagedAsync(requests, 20, cancellationToken);
        }

        [HttpGet("{id:Guid}")]
        public async ValueTask<ApiResult<Request>> GetSingle(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            var request = await db.Requests
                .Include(x => x.Certificate)
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (request == null)
            {
                return ApiResult<Request>(404, "The specified request is not found");
            }

            return ApiResult(request);
        }

        [HttpPost]
        public async ValueTask<ApiResult<Request>> Post(
            [FromServices] IConfiguration configuration,
            [FromServices] CaContext db,
            [FromServices] OpenSsl ssl,
            [FromBody] PostCertificateRequest request,
            CancellationToken cancellationToken = default)
        {
            var tempPath = configuration["OpenSsl:TempPath"];
            if (!Directory.Exists(tempPath))
            {
                Directory.CreateDirectory(tempPath);
            }

            var certRequest = new Request 
            {
                CsrContent = request.CsrContent,
                Username = User.Identity.Name,
                Status = RequestStatus.Pending,
                CommonName = request.CommonName,
                Type= request.Type,
                RequestMessage= request.RequestMessage,
                Dns = request.Dns
            };

            var guid = Guid.NewGuid();
            var certRandom = guid.ToString();
            var csrPath = Path.Combine(tempPath, certRandom + ".csr");
            if (request.Mode == RequestMode.FromInfo)
            {
                var password = certRandom.Replace("-", "").Substring(0, 8);
                var keyPath = Path.Combine(tempPath, certRandom + ".key");

                // Generate csr
                ssl.GenerateRsaPrivateKey(keyPath, password);
                ssl.GenerateCsr(
                    csrPath,
                    keyPath, 
                    password, 
                    request.Country, 
                    request.Province,
                    request.City, 
                    request.Organization, 
                    request.OrganizationUnit, 
                    request.CommonName, 
                    request.Email);
                
                certRequest.CsrContent = System.IO.File.ReadAllText(csrPath);
                System.IO.File.Delete(csrPath);
                certRequest.KeyContent = System.IO.File.ReadAllText(keyPath);
                System.IO.File.Delete(keyPath);
                certRequest.KeyPassword = password;
            }

            await System.IO.File.WriteAllTextAsync(csrPath, request.CsrContent, cancellationToken);
            request.CommonName = ssl.GetCommonNameFromCsr(csrPath);

            db.Requests.Add(certRequest);
            await db.SaveChangesAsync(cancellationToken);

            return ApiResult(certRequest);
        }

        [HttpPatch("{id:Guid}")]
        public async ValueTask<ApiResult> Patch(
            [FromServices] IConfiguration configuration,
            [FromServices] CaContext db,
            [FromServices] OpenSsl ssl,
            [FromRoute] Guid id,
            [FromBody] PatchCertificateRequest request,
            CancellationToken cancellationToken = default)
        {
            // TODO: Check permission

            var certRequest = db.Requests
                .Where(x => x.Id == id);

            LolitaSetting<Request> query = null;

            if (request.Dns != null)
            {
                query = certRequest.SetField(x => x.Dns).WithValue(request.Dns);
            }

            if (query == null)
            {
                return ApiResult(400, "No field updated");
            }

            var affectedRows = await query.UpdateAsync(cancellationToken);
            if (affectedRows == 0)
            {
                return ApiResult(404, "Request not found");
            }

            return ApiResult(200, "Request updated");
        }

        [HttpPost("{id:Guid}/signature")]
        public async ValueTask<ApiResult<Guid>> Post(
            [FromServices] IConfiguration configuration,
            [FromServices] CaContext db,
            [FromServices] OpenSsl ssl,
            [FromRoute] Guid id,
            [FromBody] PostSignCertificateRequest request,
            CancellationToken cancellationToken = default)
        {
            // TODO: Check permission

            var tempPath = configuration["OpenSsl:TempPath"];
            var certRequest = await db.Requests
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certRequest == null)
            {
                return ApiResult<Guid>(404, "Request not found");
            }

            var guid = Guid.NewGuid();
            var certRandom = guid.ToString();
            var csrPath = Path.Combine(tempPath, certRandom + ".csr");
            var crtPath = Path.Combine(tempPath, certRandom + ".crt");
            var keyPath = Path.Combine(tempPath, certRandom + ".key");
            var caKeyPath = Path.Combine(tempPath, certRandom + ".ca.key");
            var caCrtPath = Path.Combine(tempPath, certRandom + ".ca.crt");
            var tempFiles = new[] { csrPath, crtPath, keyPath, caKeyPath, caCrtPath };
            await System.IO.File.WriteAllTextAsync(csrPath, certRequest.CsrContent, cancellationToken);
            var commonName = ssl.GetCommonNameFromCsr(csrPath);

            var cert = new Certificate
            {
                IssuedAt = DateTime.UtcNow,
                CommonName = commonName,
                KeyPassword = certRequest.KeyPassword,
                Type = certRequest.Type,
                Username = certRequest.Username
            };

            switch (certRequest.Type)
            {
                case CertificateType.RootCA:
                    {
                        await System.IO.File.WriteAllTextAsync(keyPath, certRequest.KeyContent, cancellationToken);
                        ssl.GenerateSelfSignedCert(csrPath, keyPath, crtPath, request.Days, certRequest.KeyPassword, request.Algorithm);
                        break;
                    }
                case CertificateType.IntermediateCA:
                    {
                        if (request.CaCertificateId == null)
                        {
                            return ApiResult<Guid>(400, "CaCertificateId must be specified");
                        }

                        var caCert = await db.Certificates
                            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

                        if (caCert == null)
                        {
                            return ApiResult<Guid>(400, "CA Certificate not found");
                        }

                        await System.IO.File.WriteAllTextAsync(caKeyPath, caCert.KeyFile, cancellationToken);
                        await System.IO.File.WriteAllTextAsync(caCrtPath, caCert.CrtFile, cancellationToken);
                        ssl.SignIntermediateCaCert(
                            csrPath, crtPath, request.Days, caCrtPath, caKeyPath, 
                            caCert.KeyPassword, request.Algorithm, request.CrlUrls);
                        cert.CrlUrls = string.Join(",", request.CrlUrls);
                        cert.ParentId = caCert.Id;
                        break;
                    }
                case CertificateType.Server:
                    {
                        if (request.CaCertificateId == null)
                        {
                            return ApiResult<Guid>(400, "CaCertificateId must be specified");
                        }

                        var caCert = await db.Certificates
                            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

                        if (caCert == null)
                        {
                            return ApiResult<Guid>(400, "CA Certificate not found");
                        }

                        ssl.SignServerCert(
                            csrPath, crtPath, request.Days, caCrtPath, caKeyPath,
                            caCert.KeyPassword, request.Algorithm, certRequest.Dns.Split(';'), caCert.CrlUrls.Split(';'));
                        cert.CrlUrls = string.Join(",", caCert.CrlUrls);
                        cert.ParentId = caCert.Id;
                        break;
                    }
                case CertificateType.Client:
                    {
                        if (request.CaCertificateId == null)
                        {
                            return ApiResult<Guid>(400, "CaCertificateId must be specified");
                        }

                        var caCert = await db.Certificates
                            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

                        if (caCert == null)
                        {
                            return ApiResult<Guid>(400, "CA Certificate not found");
                        }

                        ssl.SignClientCert(
                            csrPath, crtPath, request.Days, caCrtPath, caKeyPath,
                            caCert.KeyPassword, request.Algorithm, caCert.CrlUrls.Split(';'));
                        cert.CrlUrls = string.Join(",", caCert.CrlUrls);
                        cert.ParentId = caCert.Id;
                        break;
                    }
                case CertificateType.CodeSigning:
                    {
                        if (request.CaCertificateId == null)
                        {
                            return ApiResult<Guid>(400, "CaCertificateId must be specified");
                        }

                        var caCert = await db.Certificates
                            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

                        if (caCert == null)
                        {
                            return ApiResult<Guid>(400, "CA Certificate not found");
                        }

                        ssl.SignCodeSigningCert(
                            csrPath, crtPath, request.Days, caCrtPath, caKeyPath,
                            caCert.KeyPassword, request.Algorithm, caCert.CrlUrls.Split(';'));
                        cert.CrlUrls = string.Join(",", caCert.CrlUrls);
                        cert.ParentId = caCert.Id;
                        break;
                    }
            }

            cert.CrtFile = await System.IO.File.ReadAllTextAsync(crtPath, cancellationToken);

            db.Certificates.Add(cert);
            certRequest.CertificateId = cert.Id;
            certRequest.Status = RequestStatus.Approved;
            await db.SaveChangesAsync(cancellationToken);

            foreach (var file in tempFiles)
            { 
                if (System.IO.File.Exists(file))
                {
                    System.IO.File.Delete(file);
                }
            }

            return ApiResult(cert.Id);
        }
    }
}
