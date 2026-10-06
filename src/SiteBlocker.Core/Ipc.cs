using System.Text.Json;
using System.Text.Json.Serialization;

namespace SiteBlocker.Core;

/// <summary>Протокол именованного канала \\.\pipe\SiteBlocker.v1: одна JSON-строка запрос → одна строка ответ.</summary>
public static class Ipc
{
    public const string PipeName = "SiteBlocker.v1";

    public const string CmdStatus = "status";
    public const string CmdSetup = "setup";               // первый запуск: задать пароль и список (клиент становится владельцем)
    public const string CmdUnlock = "unlock";             // {password, extraMinutes}
    public const string CmdLock = "lock";                 // заблокировать сейчас (ужесточение — без пароля)
    public const string CmdChangePassword = "changePass"; // {oldPassword, newPassword}
    public const string CmdSaveSettings = "saveSettings"; // {password, settings}
    public const string CmdMaintToken = "maintToken";     // {password} → одноразовый токен для удаления/обновления
    public const string CmdBeginMaint = "beginMaint";     // {token} от установщика (админ)
    public const string CmdHistory = "history";
}

public sealed class IpcRequest
{
    [JsonPropertyName("cmd")] public string Cmd { get; set; } = "";
    [JsonPropertyName("password")] public string? Password { get; set; }
    [JsonPropertyName("newPassword")] public string? NewPassword { get; set; }
    [JsonPropertyName("settings")] public Settings? Settings { get; set; }
    [JsonPropertyName("extraMinutes")] public int? ExtraMinutes { get; set; }
    [JsonPropertyName("token")] public string? Token { get; set; }
}

public sealed class StatusDto
{
    [JsonPropertyName("configured")] public bool Configured { get; set; }   // пароль задан (установка завершена)
    [JsonPropertyName("isOwner")] public bool IsOwner { get; set; }         // клиент — учётка-владелец
    [JsonPropertyName("ownerName")] public string OwnerName { get; set; } = "";
    [JsonPropertyName("enabled")] public bool Enabled { get; set; }
    [JsonPropertyName("blocked")] public bool Blocked { get; set; }         // сейчас действует блокировка
    [JsonPropertyName("unlocked")] public bool Unlocked { get; set; }
    [JsonPropertyName("unlockUntil")] public long UnlockUntil { get; set; } // 0 + untilSession → до конца сеанса
    [JsonPropertyName("untilSession")] public bool UntilSession { get; set; }
    [JsonPropertyName("sitesCount")] public int SitesCount { get; set; }
    [JsonPropertyName("settings")] public Settings Settings { get; set; } = new();
    [JsonPropertyName("serviceVersion")] public string ServiceVersion { get; set; } = "";
    [JsonExtensionData] public Dictionary<string, JsonElement>? Extra { get; set; }
}

public sealed class IpcResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("status")] public StatusDto? Status { get; set; }
    [JsonPropertyName("token")] public string? Token { get; set; }
    [JsonPropertyName("tokenExpiresAt")] public long TokenExpiresAt { get; set; }
    [JsonPropertyName("history")] public HistoryFile? History { get; set; }

    public static IpcResponse Fail(string e) => new() { Ok = false, Error = e };
}
