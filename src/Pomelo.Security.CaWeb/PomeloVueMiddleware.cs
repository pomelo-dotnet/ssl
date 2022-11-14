using System;
using System.IO;
using System.Threading.Tasks;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;

namespace Pomelo.Security.CaWeb
{
    public class PomeloVueMiddleware
    {
        private readonly RequestDelegate _next;

        private readonly string _main;

        public PomeloVueMiddleware(RequestDelegate next)
        {
            _next = next;
            _main = File.ReadAllText("default.html");
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Path.ToString().StartsWith("/api", StringComparison.OrdinalIgnoreCase))
            {
                await _next(httpContext);
                return;
            }

#if DEBUG
            var webRootPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "../../../wwwroot");
#else
            var webRootPath = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "wwwroot");
#endif
            var path = Path.Combine(webRootPath, httpContext.Request.Path.ToString().Split('?')[0].Trim('/'));
            if (File.Exists(path + ".html") || File.Exists(path + "/index.html") || File.Exists(path + ".m.html") || File.Exists(path + "/index.m.html") || File.Exists(path + "/main.html"))
            {
                httpContext.Response.StatusCode = 200;
                httpContext.Response.ContentType = "text/html";
                if (File.Exists(path + ".html") && path.Substring(webRootPath.Length).Trim('/').IndexOf('/') == -1)
                {
                    await httpContext.Response.WriteAsync(File.ReadAllText(path + ".html"));
                }
                else if (File.Exists(path + ".m.html") && path.Substring(webRootPath.Length).Trim('/').IndexOf('/') == -1)
                {
                    await httpContext.Response.WriteAsync(File.ReadAllText(path + ".m.html"));
                }
                else
                {
                    await httpContext.Response.WriteAsync(_main);
                }
                await httpContext.Response.CompleteAsync();
                httpContext.Response.Body.Close();
                return;
            }
            else if (string.IsNullOrEmpty(Path.GetExtension(path))) 
            {
                await httpContext.Response.WriteAsync(_main);
                await httpContext.Response.CompleteAsync();
                httpContext.Response.Body.Close();
                return;
            }
            await _next(httpContext);
        }
    }

    public static class PomeloVueMiddlewareExtensions
    {
        public static IApplicationBuilder UsePomeloVueMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<PomeloVueMiddleware>();
        }
    }
}
