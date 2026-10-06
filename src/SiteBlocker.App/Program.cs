using System;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using SiteBlocker.Core;
using SiteBlocker.Service;

namespace SiteBlocker.App;

/// <summary>
/// Точка входа SiteBlocker.exe:
///   (без ключей) / --agent     — окно/трей в сеансе пользователя;
///   --service                  — служба Windows (запускает SCM);
///   --console-service          — цикл службы в консоли (отладка);
///   --begin-maintenance [--quiet] [--token X] — установщик (админ): включить режим обслуживания;
///   --restore-policies         — снять политики блокировки для всех учёток (аварийно, от администратора).
/// </summary>
public static class Program
{
    public const string AgentMutex = @"Local\SiteBlocker.Agent.v1";
    public const string ShowEvent = @"Local\SiteBlocker.ShowMain.v1";

    public static string ExePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "SiteBlocker.exe");

    [STAThread]
    public static int Main(string[] args)
    {
        var a = args.Select(x => x.ToLowerInvariant()).ToList();
        var set = a.ToHashSet();
        if (set.Contains("--service"))
        {
            AppDomain.CurrentDomain.UnhandledException += (_, e) => Log.Write("unhandled: " + e.ExceptionObject);
            ServiceBase.Run(new SiteBlockerService(ExePath));
            return 0;
        }
        if (set.Contains("--console-service")) { SiteBlockerService.RunConsole(ExePath); return 0; }
        if (set.Contains("--begin-maintenance")) return BeginMaintenance(set.Contains("--quiet"), TokenArg(args));
        if (set.Contains("--restore-policies")) return RestorePolicies();
        return RunAgent();
    }

    private static string? TokenArg(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
            if (args[i].Equals("--token", StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static int RunAgent()
    {
        using var mutex = new Mutex(true, AgentMutex, out bool first);
        if (!first)
        {
            try { using var ev = EventWaitHandle.OpenExisting(ShowEvent); ev.Set(); } catch { }
            return 0;
        }
        using var show = new EventWaitHandle(false, EventResetMode.AutoReset, ShowEvent);
        var app = new AgentApp(show);
        return app.Run();
    }

    /// <summary>Для install.ps1 / uninstall.ps1 (админ): включить режим обслуживания по одноразовому токену.</summary>
    private static int BeginMaintenance(bool quiet, string? token)
    {
        using var pc = new PipeClient();
        if (string.IsNullOrEmpty(token)) token = ReadTokenFile();
        if (string.IsNullOrEmpty(token))
        {
            Console.Error.WriteLine("Нет разрешения. Откройте «Блокировщик сайтов», введите пароль и нажмите «Разрешить удаление/обновление».");
            return 2;
        }
        var b = pc.Request(new IpcRequest { Cmd = Ipc.CmdBeginMaint, Token = token });
        if (b == null) { Console.Error.WriteLine("Служба не отвечает: " + pc.LastError); return 3; }
        if (!b.Ok) { Console.Error.WriteLine(b.Error ?? "Отказано."); return 2; }
        try { var tf = Path.Combine(Paths.DataDir, "maint.token"); if (File.Exists(tf)) File.Delete(tf); } catch { }
        return 0;
    }

    private static string? ReadTokenFile()
    {
        try
        {
            var tf = Path.Combine(Paths.DataDir, "maint.token");
            if (!File.Exists(tf)) return null;
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(tf));
            if (doc.RootElement.TryGetProperty("value", out var v)) return v.GetString();
        }
        catch { }
        return null;
    }

    private static int RestorePolicies()
    {
        int errors = 0;
        try
        {
            var reg = new WinRegistry();
            var engine = new PolicyEngine(reg);
            var m = DataLayout.LoadMachine(Paths.DataDir);
            foreach (var sid in GuardWorker.Targets(m))
            {
                try { engine.Remove("HKU\\" + sid); } catch { errors++; }
            }
            try { Firewall.Remove(); } catch { errors++; }
        }
        catch { errors++; }
        return errors == 0 ? 0 : 1;
    }
}
