using System.Security.Cryptography;

namespace SiteBlocker.Core;

/// <summary>
/// Одноразовые токены обслуживания. Служба выдаёт токен ТОЛЬКО после проверки пароля; установщик/деинсталлятор
/// без действительного токена ничего не делают. Токен одноразовый, с TTL, привязан к цели.
/// </summary>
public sealed class MaintenanceTokens
{
    public const string Maintenance = "maintenance";
    public const long DefaultTtlMs = 15 * 60_000L;

    public sealed record Token(string Value, string Purpose, long IssuedAt, long ExpiresAt);

    private readonly object _gate = new();
    private readonly List<Token> _tokens = new();
    private readonly Func<long> _now;

    public MaintenanceTokens(Func<long> nowMs) { _now = nowMs; }

    public Token Issue(string purpose, long ttlMs = DefaultTtlMs)
    {
        lock (_gate)
        {
            Prune();
            var t = new Token(NewSecret(), purpose, _now(), _now() + ttlMs);
            _tokens.Add(t);
            return t;
        }
    }

    public bool Consume(string value, string purpose)
    {
        lock (_gate)
        {
            Prune();
            int i = _tokens.FindIndex(t => t.Purpose == purpose && FixedEquals(t.Value, value) && t.ExpiresAt >= _now());
            if (i < 0) return false;
            _tokens.RemoveAt(i);
            return true;
        }
    }

    private void Prune() { long n = _now(); _tokens.RemoveAll(t => t.ExpiresAt < n); }
    private static string NewSecret() => Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    private static bool FixedEquals(string a, string b)
    {
        var x = System.Text.Encoding.ASCII.GetBytes(a ?? ""); var y = System.Text.Encoding.ASCII.GetBytes(b ?? "");
        return x.Length == y.Length && CryptographicOperations.FixedTimeEquals(x, y);
    }
}
