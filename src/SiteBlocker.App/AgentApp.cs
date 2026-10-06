using System;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows;
using WpfApp = System.Windows.Application;
using WinForms = System.Windows.Forms;
using Drawing = System.Drawing;
using SiteBlocker.Core;

namespace SiteBlocker.App;

/// <summary>Приложение в сеансе пользователя: значок в трее + главное окно. Служба сама запускает его при входе.</summary>
public sealed class AgentApp
{
    private readonly EventWaitHandle _show;
    private WpfApp? _app;
    private WinForms.NotifyIcon? _tray;
    private MainWindow? _window;
    private readonly PipeClient _pipe = new();

    public AgentApp(EventWaitHandle show) { _show = show; }

    public int Run()
    {
        _app = new WpfApp { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        _app.Startup += (_, _) =>
        {
            SetupTray();
            WatchShowEvent();
            // Первый запуск сразу показываем окно, если ещё не настроено.
            try
            {
                var st = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdStatus }, 3000);
                if (st?.Status is { Configured: false }) ShowWindow();
            }
            catch { }
        };
        return _app.Run();
    }

    private void SetupTray()
    {
        _tray = new WinForms.NotifyIcon
        {
            Icon = LoadIcon(),
            Text = "Блокировщик сайтов",
            Visible = true,
        };
        _tray.DoubleClick += (_, _) => ShowWindow();
        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Открыть", null, (_, _) => ShowWindow());
        menu.Items.Add("Заблокировать сейчас", null, (_, _) => { try { _pipe.Request(new IpcRequest { Cmd = Ipc.CmdLock }); } catch { } });
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Выход (окна)", null, (_, _) => Shutdown());
        _tray.ContextMenuStrip = menu;
    }

    private static Drawing.Icon LoadIcon()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            using var s = asm.GetManifestResourceStream("siteblocker.ico");
            if (s != null) return new Drawing.Icon(s);
        }
        catch { }
        return Drawing.SystemIcons.Application;
    }

    private void WatchShowEvent()
    {
        var t = new Thread(() =>
        {
            while (true)
            {
                try { _show.WaitOne(); _app?.Dispatcher.Invoke(ShowWindow); }
                catch { Thread.Sleep(500); }
            }
        }) { IsBackground = true, Name = "SiteBlocker.ShowWatch" };
        t.Start();
    }

    private void ShowWindow()
    {
        if (_window == null)
        {
            _window = new MainWindow(_pipe);
            _window.Closed += (_, _) => _window = null;
        }
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
        _window.Topmost = true; _window.Topmost = false;
        _window.Refresh();
    }

    private void Shutdown()
    {
        try { if (_tray != null) _tray.Visible = false; } catch { }
        _app?.Shutdown();
    }
}
