using System.Runtime.InteropServices;

namespace SiteBlocker.Service;

/// <summary>P/Invoke: WTS, токены, CreateProcessAsUser, часы, pipe.</summary>
public static unsafe class Native
{
    public const uint WTS_CURRENT_SERVER_HANDLE = 0;
    public const uint INVALID_SESSION = 0xFFFFFFFF;

    public enum WTS_CONNECTSTATE_CLASS { Active, Connected, ConnectQuery, Shadow, Disconnected, Idle, Listen, Reset, Down, Init }
    public enum WTS_INFO_CLASS { WTSUserName = 5, WTSConnectState = 8, WTSSessionInfoEx = 25 }

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO { public uint SessionId; public IntPtr pWinStationName; public WTS_CONNECTSTATE_CLASS State; }

    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr ppSessionInfo, out int count);
    // ВАЖНО: явно W-версия. В 1.0.0 здесь не было CharSet, и .NET вызывал WTSQuerySessionInformationA:
    // ANSI-структура разбиралась как Unicode, имя пользователя получалось мусором/пустым → «нет пользователя»
    // → служба считала сеанс непригодным и время не шло.
    [DllImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, WTS_INFO_CLASS cls, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr p);

    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true)] public static extern bool GetTokenInformation(IntPtr token, int cls, out int info, int len, out int retLen);
    [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
    [DllImport("kernel32.dll")] public static extern bool QueryUnbiasedInterruptTime(out ulong unbiased100ns);

    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public enum SECURITY_IMPERSONATION_LEVEL { Anonymous, Identification, Impersonation, Delegation }
    public enum TOKEN_TYPE { Primary = 1, Impersonation }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attrs, SECURITY_IMPERSONATION_LEVEL level, TOKEN_TYPE type, out IntPtr newToken);
    [DllImport("userenv.dll", SetLastError = true)] public static extern bool CreateEnvironmentBlock(out IntPtr env, IntPtr token, bool inherit);
    [DllImport("userenv.dll", SetLastError = true)] public static extern bool DestroyEnvironmentBlock(IntPtr env);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint NORMAL_PRIORITY_CLASS = 0x00000020;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(IntPtr token, string? app, System.Text.StringBuilder cmdLine, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string? cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint sessionId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint pid);

    // --- Идентификация клиента канала по PID (без имперсонации; работает при любом уровне токена и в lockdown) ---
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint TOKEN_QUERY = 0x0008;
    public const int TokenUser = 1;
    public const int TokenElevation = 20;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    // Буферный вариант GetTokenInformation (для TokenUser → TOKEN_USER со PSID).
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr token, int cls, IntPtr buffer, int len, out int retLen);

    // Смещения в WTSINFOEXW (x64 и x86 одинаково: объединение выровнено по 8 из-за LARGE_INTEGER):
    // Level @0, Data @8 → SessionId @8, SessionState @12, SessionFlags @16, WinStationName @20, UserName @86.
    public const int WTSINFOEX_LEVEL_OFFSET = 0;
    public const int WTSINFOEX_SESSIONFLAGS_OFFSET = 16;
    public const int WTS_SESSIONSTATE_UNKNOWN = unchecked((int)0xFFFFFFFF);

    // WTSINFOEX (уровень 1) — состояние блокировки рабочего стола (структура оставлена для справки; читаем по смещениям)
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSINFOEX_LEVEL1
    {
        public uint SessionId; public WTS_CONNECTSTATE_CLASS SessionState; public int SessionFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string WinStationName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)] public string UserName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 18)] public string DomainName;
        public long LogonTime, ConnectTime, DisconnectTime, LastInputTime, CurrentTime;
        public uint IncomingBytes, OutgoingBytes, IncomingFrames, OutgoingFrames, IncomingCompressedBytes, OutgoingCompressedBytes;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct WTSINFOEX { public uint Level; public WTSINFOEX_LEVEL1 Data; }
    public const int WTS_SESSIONSTATE_LOCK = 0;
    public const int WTS_SESSIONSTATE_UNLOCK = 1;
}
