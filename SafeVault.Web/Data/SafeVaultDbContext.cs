using Microsoft.EntityFrameworkCore;
using SafeVault.Web.Models;

namespace SafeVault.Web.Data;

public class SafeVaultDbContext : DbContext
{
    public SafeVaultDbContext(DbContextOptions<SafeVaultDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
    public DbSet<UserCredential> UserCredentials { get; set; }
    public DbSet<FinancialRecord> FinancialRecords { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserID);
            entity.HasIndex(e => e.Username).IsUnique();
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Username).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Email).IsRequired().HasMaxLength(100);
        });

        // Configure UserCredential entity
        modelBuilder.Entity<UserCredential>(entity =>
        {
            entity.HasKey(e => e.CredentialID);
            entity.HasIndex(e => e.UserID).IsUnique();
            entity.Property(e => e.PasswordHash).IsRequired();
            
            entity.HasOne(e => e.User)
                  .WithOne(u => u.Credential)
                  .HasForeignKey<UserCredential>(e => e.UserID)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure FinancialRecord entity
        modelBuilder.Entity<FinancialRecord>(entity =>
        {
            entity.HasKey(e => e.RecordID);
            entity.Property(e => e.Description).IsRequired().HasMaxLength(200);
            entity.Property(e => e.EncryptedData).IsRequired();
            entity.Property(e => e.Amount).HasColumnType("decimal(18,2)");
            
            entity.HasOne(e => e.User)
                  .WithMany(u => u.FinancialRecords)
                  .HasForeignKey(e => e.UserID)
                  .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
