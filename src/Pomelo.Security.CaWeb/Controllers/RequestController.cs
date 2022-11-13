using System;
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
    }
}
