using System.Security.Cryptography;
using System.Text;

namespace SiteBlocker.Core;

/// <summary>Хэширование пароля PBKDF2-SHA256 с солью. Пароль в открытом виде нигде не хранится.</summary>
public static class PasswordHash
{
    public const int Iterations = 210_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public static AuthData Create(string password, long nowMs)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Derive(password, salt, Iterations);
        return new AuthData
        {
            Alg = "pbkdf2-sha256",
            Iterations = Iterations,
            Salt = Convert.ToBase64String(salt),
            Hash = Convert.ToBase64String(hash),
            CreatedAt = nowMs,
        };
    }

    /// <summary>Проверка пароля в постоянное время.</summary>
    public static bool Verify(AuthData? auth, string password)
    {
        if (auth == null || string.IsNullOrEmpty(auth.Salt) || string.IsNullOrEmpty(auth.Hash)) return false;
        byte[] salt, expected;
        try { salt = Convert.FromBase64String(auth.Salt); expected = Convert.FromBase64String(auth.Hash); }
        catch { return false; }
        int iter = auth.Iterations > 0 ? auth.Iterations : Iterations;
        var actual = Derive(password, salt, iter, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static byte[] Derive(string password, byte[] salt, int iterations, int len = HashBytes)
    {
        using var k = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(password ?? ""), salt, iterations, HashAlgorithmName.SHA256);
        return k.GetBytes(len);
    }
}
