using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using DevInSales.Core.Entities;

namespace DevInSales.Core.Data.Mappings
{
    public class SaleMap : IEntityTypeConfiguration<Sale>
    {
        public void Configure(EntityTypeBuilder<Sale> builder)
        {
            builder.ToTable("Sales");

            // Opcional, pois por convenção nossa propriedade já seria a chave primária
            builder.HasKey(p => p.Id);

            builder.Property(p => p.SaleDate);

            builder.HasOne(p => p.Buyer)
                .WithMany()
                .HasForeignKey(p => p.BuyerId)
                .OnDelete(DeleteBehavior.NoAction);           

            builder.HasOne(p => p.Seller)
                .WithMany()
                .HasForeignKey(p => p.SellerId)
                .OnDelete(DeleteBehavior.NoAction); 
        }
    }
}