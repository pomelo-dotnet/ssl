using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Pomelo.Security.CaWeb.Models;
using Pomelo.Security.CaWeb.Utils;

namespace Pomelo.Security.CaWeb
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddPomeloOpenSsl(Configuration["OpenSsl:Path"]);
            if (Configuration["Database:Type"] == "MySQL")
            {
                services.AddDbContext<CaContext>(x => 
                {
                    x.UseMySql(Configuration["Database:ConnectionString"], new MySqlServerVersion(new Version(8, 0, 31)));
                    x.UseMySqlLolita();
                });
            }
            else if (Configuration["Database:Type"] == "SQLite")
            {
                services.AddDbContext<CaContext>(x => 
                {
                    x.UseSqlite("Data source=ca.db");
                    x.UseSqliteLolita();
                });
            }
            else
            {
                throw new NotSupportedException(Configuration["Database:Type"]);
            }
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UsePomeloVueMiddleware();
            app.UseRouting();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
