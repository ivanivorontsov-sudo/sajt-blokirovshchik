using System.ServiceProcess;

namespace SiteBlocker.Service;

/// <summary>Хост службы Windows «SiteBlocker» (LocalSystem, автозапуск, перезапуск при сбое — настраивает установщик).</summary>
public sealed class SiteBlockerService : ServiceBase
{
    private GuardWorker? _worker;
    private readonly string _exe;

    public SiteBlockerService(string exePath)
    {
        _exe = exePath;
        ServiceName = Paths.ServiceName;
        CanHandleSessionChangeEvent = true;
        CanHandlePowerEvent = true;
        CanShutdown = true;
        CanStop = true;
        AutoLog = true;
        ServiceControl.Bind(() => ServiceHandle);
    }

    protected override void OnStart(string[] args) { _worker = new GuardWorker(_exe); _worker.Start(); }
    protected override void OnStop() { _worker?.Stop(removePolicies: true); }
    protected override void OnShutdown() { _worker?.Stop(removePolicies: false); }

    protected override void OnSessionChange(SessionChangeDescription d)
    {
        Log.Write($"session {d.SessionId}: {d.Reason}");
        Sessions.OnSessionEvent((uint)d.SessionId, d.Reason);
        _worker?.Wake();
    }
    protected override bool OnPowerEvent(PowerBroadcastStatus s) { _worker?.Wake(); return true; }

    public static void RunConsole(string exe)
    {
        var w = new GuardWorker(exe);
        w.Start();
        Console.WriteLine("SiteBlocker guard запущен в консоли. Enter — остановить.");
        Console.ReadLine();
        w.Stop(true);
    }
}
