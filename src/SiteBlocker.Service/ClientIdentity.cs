using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SiteBlocker.Service;

/// <summary>Кто подключился к каналу: SID пользователя и признак «с повышением» (elevated).</summary>
public sealed record ClientId(string? Sid, bool Elevated, string Method, string? Diag);

/// <summary>
/// Определение клиента именованного канала БЕЗ имперсонации.
/// Основной путь: GetNamedPipeClientProcessId → OpenProcess(QUERY_LIMITED) → OpenProcessToken(QUERY) →
/// GetTokenInformation(TokenUser) для SID и TokenElevation для признака повышения.
/// Это надёжнее RunAsClient/ImpersonateNamedPipeClient: работает при любом TokenImpersonationLevel клиента
/// и не требует права имперсонации (в 1.0.0 RunAsClient падал с пустым сообщением на каждый запрос).
/// </summary>
public static class ClientIdentity
{
    /// <summary>Определить клиента по хэндлу серверного конца канала (PID-путь, без имперсонации).</summary>
    public static ClientId Resolve(SafePipeHandle pipe)
    {
        var diags = new List<string>();
        try
        {
            if (Native.GetNamedPipeClientProcessId(pipe.DangerousGetHandle(), out uint pid) && pid != 0)
            {
                var id = FromPid(pid, diags);
                if (id != null) return id;
            }
            else diags.Add("GetNamedPipeClientProcessId win32=" + Marshal.GetLastWin32Error());
        }
        catch (Exception e) { diags.Add("pid: " + Describe(e)); }
        return new ClientId(null, false, "none", diags.Count > 0 ? string.Join("; ", diags) : null);
    }

    public static ClientId? FromPid(uint pid, List<string> diags)
    {
        IntPtr proc = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (proc == IntPtr.Zero) { diags.Add("OpenProcess pid=" + pid + " win32=" + Marshal.GetLastWin32Error()); return null; }
        try
        {
            if (!Native.OpenProcessToken(proc, Native.TOKEN_QUERY, out IntPtr tok))
            { diags.Add("OpenProcessToken pid=" + pid + " win32=" + Marshal.GetLastWin32Error()); return null; }
            try
            {
                string? sid = TokenUserSid(tok, diags);
                if (sid == null) return null;
                return new ClientId(sid, TokenElevated(tok), "pid-token", null);
            }
            finally { Native.CloseHandle(tok); }
        }
        finally { Native.CloseHandle(proc); }
    }

    private static string? TokenUserSid(IntPtr tok, List<string> diags)
    {
        Native.GetTokenInformation(tok, Native.TokenUser, IntPtr.Zero, 0, out int len);
        if (len <= 0) { diags.Add("TokenUser size win32=" + Marshal.GetLastWin32Error()); return null; }
        IntPtr buf = Marshal.AllocHGlobal(len);
        try
        {
            if (!Native.GetTokenInformation(tok, Native.TokenUser, buf, len, out _))
            { diags.Add("GetTokenInformation(TokenUser) win32=" + Marshal.GetLastWin32Error()); return null; }
            // TOKEN_USER = SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes }; первый указатель — PSID.
            IntPtr pSid = Marshal.ReadIntPtr(buf);
            if (pSid == IntPtr.Zero) { diags.Add("TokenUser PSID null"); return null; }
            return new SecurityIdentifier(pSid).Value;
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static bool TokenElevated(IntPtr tok)
    {
        try { if (Native.GetTokenInformation(tok, Native.TokenElevation, out int elev, 4, out _)) return elev != 0; }
        catch { }
        return false;
    }

    /// <summary>Подробная диагностика исключения: тип + HResult + Win32 + сообщение (пустое помечается явно).</summary>
    public static string Describe(Exception e)
        => e.GetType().Name
           + " hr=0x" + e.HResult.ToString("X8")
           + (e is Win32Exception w ? " win32=" + w.NativeErrorCode : "")
           + " msg=" + (string.IsNullOrEmpty(e.Message) ? "<пусто>" : e.Message);
}
