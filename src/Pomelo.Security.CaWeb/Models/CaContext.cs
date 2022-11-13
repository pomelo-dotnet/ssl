using Microsoft.EntityFrameworkCore;

namespace Pomelo.Security.CaWeb.Models
{
    public class CaContext : DbContext
    {
        public CaContext(DbContextOptions<CaContext> opt) : base(opt)
        { }

        public DbSet<User> Users { get; set; }

        public DbSet<Certificate> Certificates { get; set; }

        public DbSet<Request> Requests { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<User>(e =>
            {
                e.HasKey(x => x.Username);
                e.HasIndex(x => x.Role);
            });

            builder.Entity<Certificate>(e =>
            {
                e.HasIndex(x => x.IssuedAt);
                e.HasIndex(x => x.Type);
            });

            builder.Entity<Request>(e =>
            {
                e.HasIndex(x => new { x.CreatedAt, x.ValidatedAt, x.Status });
                e.HasIndex(x => x.Type);
            });
        }
    }
}
