using Microsoft.Extensions.DependencyInjection;
using Pomelo.Security.Ssl;

namespace Pomelo.Security.CaWeb.Utils
{
    public static class OpenSslExtensions
    {
        public static IServiceCollection AddPomeloOpenSsl(this IServiceCollection services, string openSslPath)
            => services.AddSingleton<OpenSsl>(x => new OpenSsl(openSslPath));
    }
}
