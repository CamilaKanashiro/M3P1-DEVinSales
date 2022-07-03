using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using DevInSales.Core.Entities;

namespace DevInSales.Core.Data.Mappings
{
    public class DeliveryMap : IEntityTypeConfiguration<Delivery>
    {
        public void Configure(EntityTypeBuilder<Delivery> builder)
        {
            builder.ToTable("Deliveries");

            // Opcional, pois por convenção nossa propriedade já seria a chave primária
            builder.HasKey(p => p.Id);

            builder.Property(p => p.DeliveryForecast);

            builder.HasOne(p => p.Sale)
                .WithMany()
                .HasForeignKey(p => p.SaleId)
                .OnDelete(DeleteBehavior.NoAction);

            builder.HasOne(p => p.Address)
                .WithMany()
                .HasForeignKey(p => p.AddressId)
                .OnDelete(DeleteBehavior.NoAction);
        }
    }
}