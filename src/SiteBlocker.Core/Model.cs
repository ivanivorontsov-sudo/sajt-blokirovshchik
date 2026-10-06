using System.Text.Json;
using System.Text.Json.Serialization;

namespace SiteBlocker.Core;

/// <summary>Длительность разблокировки по умолчанию.</summary>
public static class UnlockDefaults
{
    public const int UntilSession = 0; // до конца сеанса (выход/перезагрузка)
}

/// <summary>
/// Настройки блокировщика для одного пользователя Windows (владельца).
/// Хранятся в %ProgramData%\SiteBlocker\users\&lt;SID&gt;\settings.json. Правило совместимости: поля только добавляются.
/// </summary>
public sealed class Settings
{
    /// <summary>Список доменов для блокировки (нормализованные хосты, напр. "youtube.com").</summary>
    [JsonPropertyName("sites")] public List<string> Sites { get; set; } = new();

    /// <summary>Вкл/выкл весь блокировщик (выключить можно только по паролю — проверяет служба).</summary>
    [JsonPropertyName("enabled")] public bool Enabled { get; set; } = true;

    /// <summary>Семейства браузеров, к которым применяются политики (ключи из BrowserPolicy.ChromiumVendors + "firefox").</summary>
    [JsonPropertyName("browsers")] public List<string> Browsers { get; set; } = new();

    /// <summary>Закрывать уже открытые браузеры при включении блокировки, чтобы политика применилась сразу.</summary>
    [JsonPropertyName("closeBrowsersOnBlock")] public bool CloseBrowsersOnBlock { get; set; } = true;

    /// <summary>Дополнительный уровень: правила брандмауэра по IP, привязанные к SID владельца (экспериментально).</summary>
    [JsonPropertyName("firewallLayer")] public bool FirewallLayer { get; set; } = false;

    /// <summary>Разрешённые длительности разблокировки в минутах (0 = до конца сеанса).</summary>
    [JsonPropertyName("allowedUnlockMinutes")] public List<int> AllowedUnlockMinutes { get; set; } = new() { 0, 15, 30, 60 };

    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }

    public static Settings Defaults() => new()
    {
        Sites = new(),
        Enabled = true,
        Browsers = BrowserPolicy.DefaultBrowsers(),
        CloseBrowsersOnBlock = true,
        FirewallLayer = false,
        AllowedUnlockMinutes = new() { 0, 15, 30, 60 },
    };

    public Settings Normalized()
    {
        Sites = Domains.NormalizeList(Sites);
        if (Browsers == null || Browsers.Count == 0) Browsers = BrowserPolicy.DefaultBrowsers();
        Browsers = Browsers.Select(b => b.Trim().ToLowerInvariant()).Where(b => b.Length > 0).Distinct().ToList();
        if (AllowedUnlockMinutes == null || AllowedUnlockMinutes.Count == 0) AllowedUnlockMinutes = new() { 0, 15, 30, 60 };
        AllowedUnlockMinutes = AllowedUnlockMinutes.Where(m => m >= 0 && m <= 24 * 60).Distinct().OrderBy(m => m).ToList();
        return this;
    }

    public Settings Clone() => Json.Deserialize<Settings>(Json.Serialize(this))!;
}

/// <summary>
/// Состояние разблокировки (на диске: state.json). Разблокировка действует либо до конца сеанса
/// (BootId + LogonSession), либо до момента UnlockUntil (Wall ms). По умолчанию всё заблокировано.
/// </summary>
public sealed class BlockState
{
    /// <summary>Сейчас разблокировано?</summary>
    [JsonPropertyName("unlocked")] public bool Unlocked { get; set; }
    /// <summary>До какого момента (Unix ms, UTC). 0 вместе с UntilSession=true — до конца сеанса.</summary>
    [JsonPropertyName("unlockUntil")] public long UnlockUntil { get; set; }
    /// <summary>true — разблокировка до выхода/перезагрузки (а не до времени).</summary>
    [JsonPropertyName("untilSession")] public bool UntilSession { get; set; }
    /// <summary>Идентификатор загрузки, при котором выдана разблокировка (смена = перезагрузка = заблокировать).</summary>
    [JsonPropertyName("bootId")] public string BootId { get; set; } = "";
    /// <summary>Сеанс входа владельца, которому выдана разблокировка (смена/выход = заблокировать).</summary>
    [JsonPropertyName("logonSession")] public uint LogonSession { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Хэш пароля (PBKDF2-SHA256). auth.json в каталоге владельца (доступ только SYSTEM).</summary>
public sealed class AuthData
{
    [JsonPropertyName("alg")] public string Alg { get; set; } = "pbkdf2-sha256";
    [JsonPropertyName("iterations")] public int Iterations { get; set; }
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";   // base64
    [JsonPropertyName("hash")] public string Hash { get; set; } = "";   // base64
    [JsonPropertyName("createdAt")] public long CreatedAt { get; set; }
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Общесистемные сведения: кто владелец (чья учётка блокируется).</summary>
public sealed class MachineConfig
{
    /// <summary>SID владельца — того, кто настроил блокировщик.</summary>
    [JsonPropertyName("ownerSid")] public string OwnerSid { get; set; } = "";
    /// <summary>SID учёток, к которым применяется блок. По умолчанию — только владелец.</summary>
    [JsonPropertyName("targetSids")] public List<string> TargetSids { get; set; } = new();
    [JsonPropertyName("installedAt")] public long InstalledAt { get; set; }
    [JsonPropertyName("lastVersion")] public string LastVersion { get; set; } = "";
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

/// <summary>Запись журнала (история попыток/действий).</summary>
public sealed class HistoryEntry
{
    public const string Info = "info";
    public const string Unlock = "unlock";
    public const string Lock = "lock";
    public const string Tamper = "tamper";
    public const string BadPassword = "badpass";
    public const string Settings = "settings";

    [JsonPropertyName("ts")] public long Ts { get; set; }
    [JsonPropertyName("kind")] public string Kind { get; set; } = Info;
    [JsonPropertyName("text")] public string Text { get; set; } = "";
}

public sealed class HistoryFile
{
    [JsonPropertyName("entries")] public List<HistoryEntry> Entries { get; set; } = new();
}

public sealed class MetaFile
{
    [JsonPropertyName("schema")] public int Schema { get; set; }
    [JsonPropertyName("installedAt")] public long InstalledAt { get; set; }
    [JsonPropertyName("lastVersion")] public string LastVersion { get; set; } = "";
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}
