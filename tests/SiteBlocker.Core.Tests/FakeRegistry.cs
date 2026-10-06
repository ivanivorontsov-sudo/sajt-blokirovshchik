using SiteBlocker.Core;

namespace SiteBlocker.Core.Tests;

/// <summary>Реестр в памяти: скаляры + списковые подключи + «деревья». Эмулирует недоступный куст.</summary>
public sealed class FakeRegistry : IRegistry
{
    public readonly Dictionary<string, int> Dwords = new(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, string> Strings = new(StringComparer.OrdinalIgnoreCase);
    public readonly Dictionary<string, List<string>> Lists = new(StringComparer.OrdinalIgnoreCase);
    public readonly HashSet<string> Keys = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Unavailable = new(StringComparer.OrdinalIgnoreCase);

    private void Check(string key) { foreach (var u in Unavailable) if (key.StartsWith(u, StringComparison.OrdinalIgnoreCase)) throw new IOException("hive not loaded"); }

    public int? GetDword(string key, string name) { Check(key); return Dwords.TryGetValue(key + "|" + name, out var v) ? v : null; }
    public void SetDword(string key, string name, int value) { Check(key); Dwords[key + "|" + name] = value; Keys.Add(key); }
    public string? GetString(string key, string name) { Check(key); return Strings.TryGetValue(key + "|" + name, out var v) ? v : null; }
    public void SetString(string key, string name, string value) { Check(key); Strings[key + "|" + name] = value; Keys.Add(key); }
    public void DeleteValue(string key, string name) { Check(key); Dwords.Remove(key + "|" + name); Strings.Remove(key + "|" + name); }
    public bool KeyExists(string key) { Check(key); return Keys.Contains(key) || Lists.ContainsKey(key); }
    public IReadOnlyList<string> GetStringList(string listKey) { try { Check(listKey); } catch { return Array.Empty<string>(); } return Lists.TryGetValue(listKey, out var l) ? l.ToList() : Array.Empty<string>(); }
    public void SetStringList(string listKey, IReadOnlyList<string> items) { Check(listKey); Lists[listKey] = items.ToList(); Keys.Add(listKey); }
    public void DeleteKeyTree(string key)
    {
        try { Check(key); } catch { return; }
        foreach (var k in Keys.Where(k => k.Equals(key, StringComparison.OrdinalIgnoreCase) || k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase)).ToList()) Keys.Remove(k);
        foreach (var k in Lists.Keys.Where(k => k.Equals(key, StringComparison.OrdinalIgnoreCase) || k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase)).ToList()) Lists.Remove(k);
        foreach (var k in Dwords.Keys.Where(k => k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase) || k.StartsWith(key + "|", StringComparison.OrdinalIgnoreCase)).ToList()) Dwords.Remove(k);
        foreach (var k in Strings.Keys.Where(k => k.StartsWith(key + "\\", StringComparison.OrdinalIgnoreCase) || k.StartsWith(key + "|", StringComparison.OrdinalIgnoreCase)).ToList()) Strings.Remove(k);
    }
}
