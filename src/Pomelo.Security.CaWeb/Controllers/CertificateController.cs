using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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

        [HttpGet("{id:Guid}.crt")]
        public async ValueTask<IActionResult> GetCrt(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            var certificate = await db.Certificates
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return NotFound();
            }

            return File(Encoding.UTF8.GetBytes(certificate.CrtFile), "application/x-x509-ca-cert", id + ".crt");
        }

        [HttpGet("{id:Guid}.key")]
        public async ValueTask<IActionResult> GetKey(
            [FromServices] CaContext db,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            // TODO: Check permission

            var certificate = await db.Certificates
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return NotFound();
            }

            return File(Encoding.UTF8.GetBytes(certificate.CrtFile), "application/octet-stream", id + ".key");
        }

        [HttpPost("{id:Guid}.pfx")]
        public async ValueTask<IActionResult> PostConvertPfx(
            [FromServices] CaContext db,
            [FromServices] IConfiguration configuration,
            [FromServices] OpenSsl ssl,
            [FromBody] PostConvertPfxRequest request,
            [FromRoute] Guid id,
            CancellationToken cancellationToken = default)
        {
            // TODO: Check permission

            if (string.IsNullOrWhiteSpace(request.PfxPassword))
            {
                return BadRequest("The password must be filled");
            }

            var certificate = await db.Certificates
                .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

            if (certificate == null)
            {
                return NotFound();
            }

            // Prepare files to convert
            var tempFolder = Path.Combine(configuration["OpenSsl:TempPath"], Guid.NewGuid().ToString());
            Directory.CreateDirectory(tempFolder);
            var crtPath = Path.Combine(tempFolder, "cert.crt");
            System.IO.File.WriteAllText(crtPath, certificate.CrtFile);
            var keyPath = Path.Combine(tempFolder, "cert.key");
            var pfxPath = Path.Combine(tempFolder, "cert.pfx");
            if (request.Key != null)
            {
                System.IO.File.WriteAllText(keyPath, request.Key);
            }
            else
            {
                System.IO.File.WriteAllText(keyPath, certificate.KeyFile);
            }

            try
            {
                ssl.ConvertCrtAndKeyToPfx(crtPath, keyPath, pfxPath, request.KeyPassword ?? certificate.KeyPassword, request.PfxPassword);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }

            var bytes = await System.IO.File.ReadAllBytesAsync(pfxPath, cancellationToken);

            // Clean up
            if (Directory.Exists(tempFolder))
            {
                Directory.Delete(tempFolder, true);
            }

            return File(bytes, "application/octet-stream", id + ".pfx");
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
