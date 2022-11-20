using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
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
    }
}
