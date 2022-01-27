using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using static NonCryptographicHelpers;
using static options;

var rand = new Random();

using (var context = new TimestampedDbContext())
{
    context.Database.EnsureDeleted();
    context.Database.EnsureCreated();
    for (int i = 0; i < 333; i++)
    {
        int bucketExponent = GetBucketExponent(context.TimestampedBucketedEntity.Count());
        var count = context.TimestampedBucketedEntity.Count();
        if(GetBucketExponent(count) != GetBucketExponent(count - 1)){
            foreach(var v in context.TimestampedBucketedEntity){
                v.EmailAddress = v.EmailAddress;
                v.BucketNo = new BucketedEntity(v.EmailAddress, bucketExponent).BucketNo;
                v.EmailUpdated = DateTime.UtcNow;
            }
        }
        context.Add(new TimestampedBucketedEntity($"{i}_{rand.Next()}@example.com", bucketExponent));
        context.SaveChanges();
    }
}


/* Fetch from bucketexponentstoringdbcontext

using (var context = new BucketExponentStoringDbContext())
using (var context2 = new BucketExponentStoringDbContext())
using (var context3 = new BucketExponentStoringDbContext())
{
    var exponents = context3.BucketExponentStoringBucketedEntities.Select(_ => _.BucketExponent).Distinct().ToList();
    foreach (var v in context.BucketExponentStoringBucketedEntities)
    {
        var bucketNumbers = exponents.Select(_ => new BucketedEntity(v.EmailAddress, _).BucketNo);
        Console.WriteLine($"EmailAddress: {v.EmailAddress}");
        Console.WriteLine($"BucketNo: {v.BucketNo}");
        Console.WriteLine($"Others: {context2.BucketExponentStoringBucketedEntities.Where(_ => bucketNumbers.Contains(_.BucketNo)).Count()}");

    }
}*/

// DbContexts
public static class options
{
    public static string conn = "server=localhost;port=3306;database=tmp;uid=devuser;pwd=Pa55w0rd!";
    public static ServerVersion srvvrs = ServerVersion.Parse("8.0.27-mysql");
}


public class UnencryptedDbContext : DbContext
{
    public DbSet<BasicEntity> BasicEntities { get; set; }
    public UnencryptedDbContext() : base() { }

    protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseMySql(conn, srvvrs);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BasicEntity>(e =>
        {
            e.HasIndex(e => e.EmailAddress)
            .IsUnique();
            e.Property(e => e.EmailAddress)
            .IsRequired();
        }
        );
    }
}
public class BasicEncryptedDbContext : DbContext
{

    public DbSet<BasicEntity> BasicEntities { get; set; }
    public BasicEncryptedDbContext() : base() { }
    protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseMySql(conn, srvvrs);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BasicEntity>(e =>
        {
            e.HasIndex(e => e.EmailAddress)
            .IsUnique();
            e.Property(e => e.EmailAddress)
            .IsRequired().HasConversion<PersonalDataConverter>();
        });
    }
}

public class BucketedEncryptedDbContext : DbContext
{
    public DbSet<BucketedEntity> BucketedEntities { get; set; }
    public BucketedEncryptedDbContext() : base() { }

    protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseMySql(conn, srvvrs);

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BucketedEntity>(e =>
        {
            e.HasIndex(e => e.EmailAddress)
            .IsUnique();
            e.HasIndex(e => e.BucketNo);
            e.Property(e => e.EmailAddress)
            .IsRequired().HasConversion<PersonalDataConverter>();
        }
        );
    }
}

public class BucketExponentStoringDbContext : DbContext{
    public DbSet<BucketExponentStoringBucketedEntity> BucketExponentStoringBucketedEntities { get; set; }
    public BucketExponentStoringDbContext() : base() { }

    protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseMySql(conn, srvvrs);
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<BucketExponentStoringBucketedEntity>(e =>
        {
            e.HasIndex(e => e.EmailAddress)
            .IsUnique();
            e.HasIndex(e => e.BucketNo);
            e.HasIndex(e => e.BucketExponent);
            e.Property(e => e.EmailAddress)
            .IsRequired().HasConversion<PersonalDataConverter>();
        }
        );
    }
}

public class TimestampedDbContext : DbContext{
    public DbSet<TimestampedBucketedEntity> TimestampedBucketedEntity { get; set; }
    public TimestampedDbContext() : base() { }

    protected override void OnConfiguring(DbContextOptionsBuilder options) => options.UseMySql(conn, srvvrs);
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TimestampedBucketedEntity>(e =>
        {
            e.HasIndex(e => e.EmailAddress)
            .IsUnique();
            e.HasIndex(e => e.BucketNo);
            e.Property(e => e.EmailUpdated).ValueGeneratedOnAddOrUpdate();
            e.Property(e => e.EmailAddress)
            .IsRequired().HasConversion<PersonalDataConverter>();
        }
        );
    }
}

// Entities
public class BasicEntity
{
    public Guid Id { get; set; }
    public string EmailAddress { get; set; } = "example@example.com";
}

public class TimestampedBucketedEntity : BucketedEntity
{
    public TimestampedBucketedEntity() { }
    public TimestampedBucketedEntity(string emailAddress, int bucketExponent) : base(emailAddress, bucketExponent) { }
    public DateTime EmailUpdated { get; set; } = DateTime.UtcNow;

}

public class BucketExponentStoringBucketedEntity : BucketedEntity
{

    public BucketExponentStoringBucketedEntity() { }
    public BucketExponentStoringBucketedEntity(string emailAddress, int bucketExponent) : base(emailAddress, bucketExponent) { BucketExponent = bucketExponent; }
    public int BucketExponent { get; set; }
}

public class BucketedEntity
{
    public BucketedEntity() { }
    public BucketedEntity(string emailAddress, int bucketExponent)
    {
        BucketNo = 0;
        foreach (char c in emailAddress.ToLowerInvariant())
        {
            BucketNo += (int)c;
        }
        BucketNo %= (int)Math.Pow(2, bucketExponent);
        EmailAddress = emailAddress;
    }
    public Guid Id { get; set; }
    public string EmailAddress { get; set; } = "example@example.com";
    public int BucketNo { get; set; } = 0;
}

public class RowCountedBasicEntity
{
    public int EntryNo { get; set; } = 0;
    public Guid Id { get; set; }
    public string EmailAddress { get; set; } = "example@example.com";
}

public class RowCountedTimestampedBucketedEntity : RowCountedBucketedEntity
{
    public RowCountedTimestampedBucketedEntity() { }
    public RowCountedTimestampedBucketedEntity(string emailAddress, int bucketExponent) : base(emailAddress, bucketExponent) { }
    public DateTime EmailUpdated { get; set; } = DateTime.UtcNow;

}

public class RowCountedBucketExponentStoringBucketedEntity : RowCountedBucketedEntity
{

    public RowCountedBucketExponentStoringBucketedEntity() { }
    public RowCountedBucketExponentStoringBucketedEntity(string emailAddress, int bucketExponent) : base(emailAddress, bucketExponent) { BucketExponent = bucketExponent; }
    public int BucketExponent { get; set; }
}

public class RowCountedBucketedEntity
{
    public RowCountedBucketedEntity() { }
    public RowCountedBucketedEntity(string emailAddress, int bucketExponent)
    {
        BucketNo = 0;
        foreach (char c in emailAddress.ToLowerInvariant())
        {
            BucketNo += (int)c;
        }
        BucketNo %= (int)Math.Pow(2, bucketExponent);
        EmailAddress = emailAddress;
    }
    public Guid Id { get; set; }
    public string EmailAddress { get; set; } = "example@example.com";
    public int BucketNo { get; set; } = 0;
    public int EntryNo { get; set; } = 0;
}

public class KeyValues
{
    public string Key { get; set; }
    public int value { get; set; }
}

// Conversions
internal static class TupleExtensions
{
    public static string ToBase64String(this (string s, byte[] b) input)
    {
        return Convert.ToBase64String(input.b) + " " + input.s;
    }
}
internal static class ArrayExtensions
{
    public static string AesDecrypt(this string[] arr)
    {
        return AesEncryptionHelper.AesDecrypt(arr[1], Key.key, Convert
            .FromBase64String(arr[0]));
    }
}
public class PersonalDataConverter : ValueConverter<string, string>
{
    private const StringSplitOptions Sso =
        StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries;
    public PersonalDataConverter() : base(
        cleartext => (AesEncryptionHelper.AesEncrypt(cleartext, Key.key, null))
            .ToBase64String(),
        ciphertext => ciphertext
            .Split(" ", Sso)
            .AesDecrypt()
      , default
    )
    { }
}

// non cryptographic hash functions
public static class NonCryptographicHelpers
{
    public static int GetBucketExponent(int userCount)
    {
        if (userCount < 1) { return 1; }
        return Math.Max((int)Math.Floor(Math.Log2(userCount)) - 3, 1);
    }
}

// Encryption
public static class Key
{
    public static byte[] key = {
        (byte) 33,
        (byte) 40,
        (byte) 212,
        (byte) 209,
        (byte) 219,
        (byte) 205,
        (byte) 88,
        (byte) 100,
        (byte) 20,
        (byte) 23,
        (byte) 131,
        (byte) 149,
        (byte) 104,
        (byte) 200,
        (byte) 215,
        (byte) 17,
        (byte) 36,
        (byte) 102,
        (byte) 106,
        (byte) 19,
        (byte) 165,
        (byte) 234,
        (byte) 163,
        (byte) 139,
        (byte) 133,
        (byte) 63,
        (byte) 139,
        (byte) 249,
        (byte) 224,
        (byte) 41,
        (byte) 186,
        (byte) 209,
    };
}


public static class AesEncryptionHelper
{
    /// <summary>
    /// Encrypt the given secret using AES
    /// </summary>
    /// <param name="secret">plaintext to encrypt</param>
    /// <param name="key">The secret key to use to encrypt</param>
    /// <param name="IV">Optional initialization vector to use</param>
    /// <returns>A tuple containing the base64 encoded, encrypted ciphertext, and the initialization vector used.</returns>
    /// <exception cref="ArgumentException">Key or IV is incorrect length</exception>
    public static (string ciphertext, byte[] IV) AesEncrypt(string secret, in byte[] key, in byte[]? IV = null)
    {
        using (var aes = Aes.Create())
        {
            if (key.Length != aes.Key.Length)
            {
                throw new ArgumentException("key length incorrect");
            }
            if (IV != null && IV.Length != aes.IV.Length)
            {
                throw new ArgumentException("IV length incorrect");
            }
            aes.Key = key;
            if (IV != null)
            {
                aes.IV = IV;
            }
            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(secret);
                    }
                    return (Convert.ToBase64String(msEncrypt.ToArray()), aes.IV);
                }
            }
        }
    }
    /// <summary>
    /// Decrypt the result of <see cref="AesEncrypt"/>
    /// </summary>
    /// <param name="secret">The base64 encoded, aes encrypted ciphertext</param>
    /// <param name="key">The secret key used to encrypt the secret</param>
    /// <param name="IV">The initialization vector used to encrypt the secret</param>
    /// <returns>The decrypted plaintext</returns>
    /// <exception cref="CryptographicException">Key or IV is incorrect length</exception>
    /// <exception cref="ArgumentNullException"/>
    /// <exception cref="FormatException">Secret is not a valid base 64 string </exception>
    public static string AesDecrypt(string secret, in byte[] key, in byte[] IV)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = IV;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(secret)))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }
}