using System.Runtime.InteropServices;

namespace SiteBlocker.Service;

/// <summary>
/// Флаг «служба принимает команду Стоп». По умолчанию служба помечена как неостанавливаемая
/// (SERVICE_ACCEPT_STOP снят), поэтому даже администратор командой `sc stop` не остановит её без прохождения
/// 10 подтверждений (SCM отвечает «служба не принимает управляющие сообщения»). Команда «Завершение работы»
/// (SHUTDOWN) остаётся принятой — выключение ПК работает всегда. Перед обслуживанием/выключением флаг возвращается.
/// Это не сокрытие и не руткит: служба видна в services.msc, а Safe Mode + recovery-скрипт снимают её штатно.
/// Основную гарантию даёт DACL службы (Администраторам не даны права STOP/CONFIG/DELETE); этот флаг — второй рубеж.
/// </summary>
public static class ServiceControl
{
    // SERVICE_STATUS
    [StructLayout(LayoutKind.Sequential)]
    private struct SERVICE_STATUS
    {
        public int dwServiceType, dwCurrentState, dwControlsAccepted, dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint;
    }
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetServiceStatus(IntPtr handle, ref SERVICE_STATUS status);

    private const int SERVICE_WIN32_OWN_PROCESS = 0x10;
    private const int SERVICE_RUNNING = 0x4;
    private const int ACCEPT_STOP = 0x1, ACCEPT_SHUTDOWN = 0x4, ACCEPT_SESSIONCHANGE = 0x80, ACCEPT_POWEREVENT = 0x40;

    private static volatile Func<IntPtr>? _handle;
    public static void Bind(Func<IntPtr> statusHandle) => _handle = statusHandle;

    /// <summary>true — служба может быть остановлена SCM; false — команда «Стоп» отклоняется (SHUTDOWN остаётся).</summary>
    public static void AcceptStop(bool accept)
    {
        var h = _handle?.Invoke() ?? IntPtr.Zero;
        if (h == IntPtr.Zero) return;
        int controls = ACCEPT_SHUTDOWN | ACCEPT_SESSIONCHANGE | ACCEPT_POWEREVENT | (accept ? ACCEPT_STOP : 0);
        var st = new SERVICE_STATUS
        {
            dwServiceType = SERVICE_WIN32_OWN_PROCESS, dwCurrentState = SERVICE_RUNNING, dwControlsAccepted = controls,
        };
        try { if (!SetServiceStatus(h, ref st)) Log.Write("AcceptStop SetServiceStatus err " + Marshal.GetLastWin32Error()); }
        catch (Exception e) { Log.Write("AcceptStop: " + e.Message); }
    }
}
