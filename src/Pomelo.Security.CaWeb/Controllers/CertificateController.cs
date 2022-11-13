using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pomelo.Security.CaWeb.Models;
using Pomelo.Security.CaWeb.Models.ViewModels;

namespace Pomelo.Security.CaWeb.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class CertificateController : ControllerBase
    {
        [HttpGet]
        public async ValueTask<ApiResult<List<Certificate>>> Get(
            [FromServices] CaContext db,
            CancellationToken cancellationToken = default)
        {
            var certificates = await db.Certificates
                .Where(x => x.Type == CertificateType.RootCA)
                .ToListAsync(cancellationToken);

            return ApiResult(certificates);
        }

        [HttpGet("mine")]
        public async ValueTask<ApiResult<List<Certificate>>> GetMine(
            [FromServices] CaContext db,
            CancellationToken cancellationToken = default)
        {
            var certificates = await db.Certificates
                .Where(x => x.Username == User.Identity.Name)
                .ToListAsync(cancellationToken);

            return ApiResult(certificates);
        }

        [HttpGet("{id:Guid}")]
        public async ValueTask<ApiResult<Certificate>> GetSingle(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            var certificate = await db.Certificates
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return ApiResult<Certificate>(404, "The specified certificate is not found");
            }

            return ApiResult(certificate);
        }

        [HttpGet("{id:Guid}/children")]
        public async ValueTask<ApiResult<ICollection<Certificate>>> GetSubCertificatesOfId(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            var certificate = await db.Certificates
                .Include(x => x.Children)
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return ApiResult<ICollection<Certificate>>(404, "The specified certificate is not found");
            }

            return ApiResult(certificate.Children);
        }

        [HttpDelete("{id:Guid}")]
        public async ValueTask<ApiResult> DeleteCertificate(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            // TODO: Check user permission

            var certificate = await db.Certificates
                .Include(x => x.Children)
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return ApiResult<ICollection<Certificate>>(404, "The specified certificate is not found");
            }

            if (certificate.Type == CertificateType.RootCA)
            {
                // TODO: Revoke all intermediate certificates
            }

            // TODO: Revoke the current certificate

            db.Certificates.Remove(certificate);

            await db.SaveChangesAsync();

            return ApiResult(200, "The certificate has been revoked");
        }
    }
}
