using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using SiteBlocker.Core;

namespace SiteBlocker.Service;

public static class Paths
{
    public static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SiteBlocker");
    public static string UserDataDir(string sid) => DataLayout.UserDir(DataDir, sid);
    public static string CurrentUserDataDir
    {
        get
        {
            try { using var wi = WindowsIdentity.GetCurrent(); var sid = wi.User?.Value; if (!string.IsNullOrEmpty(sid)) return DataLayout.UserDir(DataDir, sid!); }
            catch { }
            return DataDir;
        }
    }
    public static string? CurrentUserSid
    {
        get { try { using var wi = WindowsIdentity.GetCurrent(); return wi.User?.Value; } catch { return null; } }
    }
    public static string LogDir => Path.Combine(DataDir, "logs");
    public const string ServiceName = "SiteBlocker";
    public const string ServiceDisplayName = "Блокировщик сайтов";
}

/// <summary>Часы Windows + идентификатор загрузки (BootId): смена = перезагрузка.</summary>
public sealed class WinClock
{
    private string? _boot;
    public long Mono() => (long)Native.GetTickCount64();
    public long Wall() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public string BootId => _boot ??= ReadBootId();
    private static string ReadBootId()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
            if (k?.GetValue("BootId") is int id) return "b" + id;
        }
        catch { }
        return "t" + ((DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() - (long)Native.GetTickCount64()) / 600_000);
    }
}

/// <summary>IRegistry поверх Microsoft.Win32.Registry (64-битное представление), со строками и списковыми подключами.</summary>
public sealed class WinRegistry : IRegistry
{
    private static (RegistryKey root, string sub) Split(string key)
    {
        int i = key.IndexOf('\\');
        string hive = i < 0 ? key : key[..i], sub = i < 0 ? "" : key[(i + 1)..];
        RegistryHive h = hive.ToUpperInvariant() switch
        {
            "HKLM" => RegistryHive.LocalMachine,
            "HKU" => RegistryHive.Users,
            "HKCU" => RegistryHive.CurrentUser,
            _ => throw new ArgumentException("hive " + hive),
        };
        return (RegistryKey.OpenBaseKey(h, RegistryView.Registry64), sub);
    }

    private static void EnsureHive(string key)
    {
        if (!key.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase)) return;
        var parts = key.Split('\\');
        using var u = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64).OpenSubKey(parts[1]);
        if (u == null) throw new IOException("Куст пользователя не загружен: " + parts[1]);
    }

    public int? GetDword(string key, string name)
    {
        EnsureHive(key); var (root, sub) = Split(key);
        using (root) using (var k = root.OpenSubKey(sub)) return k?.GetValue(name) is int v ? v : null;
    }
    public void SetDword(string key, string name, int value)
    {
        EnsureHive(key); var (root, sub) = Split(key);
        using (root) using (var k = root.CreateSubKey(sub, true)) k.SetValue(name, value, RegistryValueKind.DWord);
    }
    public string? GetString(string key, string name)
    {
        EnsureHive(key); var (root, sub) = Split(key);
        using (root) using (var k = root.OpenSubKey(sub)) return k?.GetValue(name) as string;
    }
    public void SetString(string key, string name, string value)
    {
        EnsureHive(key); var (root, sub) = Split(key);
        using (root) using (var k = root.CreateSubKey(sub, true)) k.SetValue(name, value, RegistryValueKind.String);
    }
    public void DeleteValue(string key, string name)
    {
        EnsureHive(key); var (root, sub) = Split(key);
        using (root) using (var k = root.OpenSubKey(sub, true)) k?.DeleteValue(name, false);
    }
    public bool KeyExists(string key)
    {
        try { EnsureHive(key); } catch { return false; }
        var (root, sub) = Split(key);
        using (root) using (var k = root.OpenSubKey(sub)) return k != null;
    }
    public IReadOnlyList<string> GetStringList(string listKey)
    {
        try { EnsureHive(listKey); } catch { return Array.Empty<string>(); }
        var (root, sub) = Split(listKey);
        using (root) using (var k = root.OpenSubKey(sub))
        {
            if (k == null) return Array.Empty<string>();
            var list = new List<string>();
            for (int i = 1; ; i++)
            {
                if (k.GetValue(i.ToString()) is string v) list.Add(v); else break;
            }
            return list;
        }
    }
    public void SetStringList(string listKey, IReadOnlyList<string> items)
    {
        EnsureHive(listKey); var (root, sub) = Split(listKey);
        using (root) using (var k = root.CreateSubKey(sub, true))
        {
            // Очистить старые числовые значения.
            foreach (var n in k.GetValueNames()) if (int.TryParse(n, out _)) k.DeleteValue(n, false);
            for (int i = 0; i < items.Count; i++) k.SetValue((i + 1).ToString(), items[i], RegistryValueKind.String);
        }
    }
    public void DeleteKeyTree(string key)
    {
        try { EnsureHive(key); } catch { return; }
        var (root, sub) = Split(key);
        using (root) { try { root.DeleteSubKeyTree(sub, false); } catch { } }
    }
}
/// <summary>Сессии Windows и запуск агента в сессии пользователя.</summary>
public static class Sessions
{
    /// <summary>
    /// Снимок консольного сеанса. Всё — через WTS (работает из сеанса 0). user32 (GetLastInputInfo, GetForegroundWindow,
    /// OpenInputDesktop) из службы НЕ используется: в сеансе 0 они видят пустой рабочий стол службы.
    /// </summary>
    public sealed record Info(uint Id, bool HasUser, bool Active, bool? Locked, bool LockFromEvents, string User, string LockSource, string? Sid)
    {
        public bool DesktopLocked => Locked == true;
        public string Describe() => $"сеанс {Id}: пользователь {(HasUser ? "«" + User + "» (" + (Sid ?? "?") + ")" : "нет")}, {(Active ? "активен" : "не активен")}, " +
                                    $"блокировка {(Locked == null ? "неизвестно" : Locked.Value ? "да" : "нет")} ({LockSource})";
    }

    // Блокировка по уведомлениям SCM (OnSessionChange: SessionLock/SessionUnlock/SessionLogon/SessionLogoff) — надёжный источник.
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<uint, bool> LockEvents = new();

    public static void OnSessionEvent(uint sessionId, System.ServiceProcess.SessionChangeReason reason)
    {
        switch (reason)
        {
            case System.ServiceProcess.SessionChangeReason.SessionLock: LockEvents[sessionId] = true; break;
            case System.ServiceProcess.SessionChangeReason.SessionUnlock:
            case System.ServiceProcess.SessionChangeReason.SessionLogon: LockEvents[sessionId] = false; break;
            case System.ServiceProcess.SessionChangeReason.SessionLogoff: LockEvents.TryRemove(sessionId, out _); break;
        }
    }

    public static Info ActiveConsole()
    {
        uint id = Native.WTSGetActiveConsoleSessionId();
        if (id == Native.INVALID_SESSION) return new Info(id, false, false, null, false, "", "нет консольного сеанса", null);
        return Describe(id);
    }

    /// <summary>Все интерактивные сеансы с вошедшим пользователем (быстрое переключение, RDP). WTSEnumerateSessions.</summary>
    public static List<Info> Enumerate()
    {
        var list = new List<Info>();
        if (!Native.WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var pp, out int count)) return list;
        try
        {
            int sz = Marshal.SizeOf<Native.WTS_SESSION_INFO>();
            for (int i = 0; i < count; i++)
            {
                var si = Marshal.PtrToStructure<Native.WTS_SESSION_INFO>(pp + i * sz);
                if (si.SessionId == 0) continue; // сеанс 0 — служебный, не пользователь
                var info = Describe(si.SessionId);
                if (info.HasUser) list.Add(info);
            }
        }
        catch { }
        finally { Native.WTSFreeMemory(pp); }
        return list;
    }

    /// <summary>Снимок одного сеанса (пользователь, активность, блокировка, SID).</summary>
    public static Info Describe(uint id)
    {
        string user = QueryString(id, Native.WTS_INFO_CLASS.WTSUserName) ?? "";
        bool hasUser = user.Length > 0;
        string? sid = UserSid(id);
        if (!hasUser && sid != null) { hasUser = true; user = "?"; }

        int? state = QueryInt(id, Native.WTS_INFO_CLASS.WTSConnectState, 0);
        bool active = state == null ? hasUser : state == (int)Native.WTS_CONNECTSTATE_CLASS.Active;

        if (LockEvents.TryGetValue(id, out var evLocked))
            return new Info(id, hasUser, active, evLocked, true, user, "уведомления Windows", sid);

        bool? locked = null;
        if (Native.WTSQuerySessionInformation(IntPtr.Zero, id, Native.WTS_INFO_CLASS.WTSSessionInfoEx, out var buf, out int bytes))
        {
            try
            {
                if (bytes >= Native.WTSINFOEX_SESSIONFLAGS_OFFSET + 4 && Marshal.ReadInt32(buf, Native.WTSINFOEX_LEVEL_OFFSET) == 1)
                {
                    int flags = Marshal.ReadInt32(buf, Native.WTSINFOEX_SESSIONFLAGS_OFFSET);
                    bool win7 = Environment.OSVersion.Version.Major == 6 && Environment.OSVersion.Version.Minor == 1;
                    if (flags == Native.WTS_SESSIONSTATE_LOCK) locked = !win7;
                    else if (flags == Native.WTS_SESSIONSTATE_UNLOCK) locked = win7;
                }
            }
            finally { Native.WTSFreeMemory(buf); }
        }
        return new Info(id, hasUser, active, locked, false, user, "WTSSessionInfoEx", sid);
    }

    private static string? QueryString(uint id, Native.WTS_INFO_CLASS cls)
    {
        if (!Native.WTSQuerySessionInformation(IntPtr.Zero, id, cls, out var buf, out _)) return null;
        try { return buf == IntPtr.Zero ? null : Marshal.PtrToStringUni(buf); }
        finally { Native.WTSFreeMemory(buf); }
    }

    private static int? QueryInt(uint id, Native.WTS_INFO_CLASS cls, int offset)
    {
        if (!Native.WTSQuerySessionInformation(IntPtr.Zero, id, cls, out var buf, out int bytes)) return null;
        try { return buf == IntPtr.Zero || bytes < offset + 4 ? null : Marshal.ReadInt32(buf, offset); }
        finally { Native.WTSFreeMemory(buf); }
    }

    public static string? UserSid(uint sessionId)
    {
        if (!Native.WTSQueryUserToken(sessionId, out var tok)) return null;
        try { using var wi = new WindowsIdentity(tok); return wi.User?.Value; }
        catch { return null; }
        finally { Native.CloseHandle(tok); }
    }

    /// <summary>WTSQueryUserToken + DuplicateTokenEx + CreateEnvironmentBlock + CreateProcessAsUser (winsta0\default).</summary>
    public static int LaunchInSession(uint sessionId, string exe, string args)
    {
        if (!Native.WTSQueryUserToken(sessionId, out var userTok))
            throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error(), "WTSQueryUserToken");
        IntPtr prim = IntPtr.Zero, env = IntPtr.Zero;
        try
        {
            if (!Native.DuplicateTokenEx(userTok, Native.MAXIMUM_ALLOWED, IntPtr.Zero, Native.SECURITY_IMPERSONATION_LEVEL.Identification, Native.TOKEN_TYPE.Primary, out prim))
                throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error(), "DuplicateTokenEx");
            Native.CreateEnvironmentBlock(out env, prim, false);
            var si = new Native.STARTUPINFO { cb = System.Runtime.InteropServices.Marshal.SizeOf<Native.STARTUPINFO>(), lpDesktop = @"winsta0\default" };
            var cmd = new System.Text.StringBuilder($"\"{exe}\" {args}");
            if (!Native.CreateProcessAsUser(prim, exe, cmd, IntPtr.Zero, IntPtr.Zero, false,
                    Native.CREATE_UNICODE_ENVIRONMENT | Native.NORMAL_PRIORITY_CLASS, env, Path.GetDirectoryName(exe), ref si, out var pi))
                throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error(), "CreateProcessAsUser");
            Native.CloseHandle(pi.hThread); Native.CloseHandle(pi.hProcess);
            return pi.dwProcessId;
        }
        finally
        {
            if (env != IntPtr.Zero) Native.DestroyEnvironmentBlock(env);
            if (prim != IntPtr.Zero) Native.CloseHandle(prim);
            Native.CloseHandle(userTok);
        }
    }

    public static bool AgentRunning(uint sessionId, string exeName)
    {
        int self = Environment.ProcessId;
        foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exeName)))
        {
            using (p) { try { if (p.Id != self && p.SessionId == sessionId) return true; } catch { } }
        }
        return false;
    }
}

/// <summary>Простой журнал службы с ротацией (1 МБ × 3).</summary>
public static class Log
{
    private static readonly object Gate = new();
    public static void Write(string msg)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Paths.LogDir);
                var p = Path.Combine(Paths.LogDir, "service.log");
                var fi = new FileInfo(p);
                if (fi.Exists && fi.Length > 1_000_000)
                {
                    var old2 = p + ".2"; var old1 = p + ".1";
                    if (File.Exists(old2)) File.Delete(old2);
                    if (File.Exists(old1)) File.Move(old1, old2);
                    File.Move(p, old1);
                }
                File.AppendAllText(p, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {msg}{Environment.NewLine}");
            }
        }
        catch { }
    }
}
