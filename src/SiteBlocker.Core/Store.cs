using System.Text.Json.Nodes;

namespace SiteBlocker.Core;

/// <summary>
/// Хранилище JSON с атомарной записью (tmp → replace), резервной копией .bak и защитой от молчаливой
/// перезаписи повреждённого файла дефолтами. Имена файлов и ключи не меняются; поля только добавляются.
/// </summary>
public sealed class Store
{
    public const string SettingsFile = "settings.json";
    public const string StateFile = "state.json";
    public const string AuthFile = "auth.json";
    public const string HistoryFile = "history.json";

    public string Dir { get; }
    private readonly object _lock = new();
    public const int MaxHistory = 2000;

    public Store(string dir) { Dir = dir; Directory.CreateDirectory(dir); }
    public string PathOf(string name) => Path.Combine(Dir, name);
    public bool Exists(string name) => File.Exists(PathOf(name)) || File.Exists(PathOf(name) + ".bak");

    public string? ReadText(string name)
    {
        lock (_lock)
        {
            var p = PathOf(name);
            foreach (var candidate in new[] { p, p + ".bak" })
            {
                if (!File.Exists(candidate)) continue;
                try { var t = File.ReadAllText(candidate); JsonNode.Parse(t); return t; }
                catch { try { File.Copy(candidate, candidate + ".corrupt-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss"), true); } catch { } }
            }
            return null;
        }
    }

    public void WriteText(string name, string text)
    {
        lock (_lock)
        {
            var p = PathOf(name);
            var tmp = p + ".tmp";
            File.WriteAllText(tmp, text);
            if (File.Exists(p)) { try { File.Copy(p, p + ".bak", true); } catch { } File.Move(tmp, p, true); }
            else File.Move(tmp, p);
        }
    }

    public void Delete(string name)
    {
        lock (_lock)
            foreach (var p in new[] { PathOf(name), PathOf(name) + ".bak" })
                try { if (File.Exists(p)) File.Delete(p); } catch { }
    }

    private T Load<T>(string name, Func<T> fallback) where T : class
    {
        var t = ReadText(name);
        if (t == null) return fallback();
        try { return Json.Deserialize<T>(t) ?? fallback(); } catch { return fallback(); }
    }

    public Settings LoadSettings() => Load(SettingsFile, Settings.Defaults).Normalized();
    public void SaveSettings(Settings s) => WriteText(SettingsFile, Json.Serialize(s.Normalized()));

    public BlockState LoadState() => Load(StateFile, () => new BlockState());
    public void SaveState(BlockState s) => WriteText(StateFile, Json.Serialize(s));

    public AuthData? LoadAuth() => Exists(AuthFile) ? Load<AuthData>(AuthFile, () => new AuthData()) : null;
    public void SaveAuth(AuthData a) => WriteText(AuthFile, Json.Serialize(a));

    public HistoryFile LoadHistory() => Load(HistoryFile, () => new HistoryFile());
    public void SaveHistory(HistoryFile h)
    {
        h.Entries = h.Entries.OrderByDescending(e => e.Ts).Take(MaxHistory).ToList();
        WriteText(HistoryFile, Json.Serialize(h));
    }
    public void Log(string kind, string text, long nowMs)
    {
        var h = LoadHistory();
        h.Entries.Insert(0, new HistoryEntry { Ts = nowMs, Kind = kind, Text = text });
        SaveHistory(h);
    }
}

/// <summary>Раскладка данных: %ProgramData%\SiteBlocker\{machine.json, users\&lt;SID&gt;\...}.</summary>
public static class DataLayout
{
    public const string MachineFile = "machine.json";
    public const string UsersDir = "users";

    public static string UsersRoot(string dataDir) => Path.Combine(dataDir, UsersDir);
    public static string UserDir(string dataDir, string sid) => Path.Combine(UsersRoot(dataDir), SafeSid(sid));

    public static string SafeSid(string sid)
    {
        sid = (sid ?? "").Trim();
        bool ok = sid.Length is > 0 and <= 190 && sid.StartsWith("S-", StringComparison.OrdinalIgnoreCase)
                  && sid.All(c => char.IsLetterOrDigit(c) || c == '-');
        return ok ? sid.ToUpperInvariant()
                  : "sid-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sid ?? "")))[..16];
    }

    public static MachineConfig LoadMachine(string dataDir)
    {
        var p = Path.Combine(dataDir, MachineFile);
        if (!File.Exists(p)) return new MachineConfig();
        try { return Json.Deserialize<MachineConfig>(File.ReadAllText(p)) ?? new MachineConfig(); } catch { return new MachineConfig(); }
    }
    public static void SaveMachine(string dataDir, MachineConfig m)
    {
        Directory.CreateDirectory(dataDir);
        var p = Path.Combine(dataDir, MachineFile);
        var tmp = p + ".tmp";
        File.WriteAllText(tmp, Json.Serialize(m));
        File.Move(tmp, p, true);
    }
}
