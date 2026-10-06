using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using SiteBlocker.Core;

namespace SiteBlocker.App;

/// <summary>Главное окно: настройка при первом запуске, затем статус и управление (всё — по паролю).</summary>
public sealed class MainWindow : Window
{
    private readonly PipeClient _pipe;
    private readonly StackPanel _root;

    public MainWindow(PipeClient pipe)
    {
        _pipe = pipe;
        Title = "Блокировщик сайтов";
        Width = 560; MinWidth = 460; SizeToContent = SizeToContent.Height;
        MaxHeight = 860;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Background = Ui.Bg;
        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _root = new StackPanel { Margin = new Thickness(22) };
        scroll.Content = _root;
        Content = scroll;
    }

    private StatusDto? Status()
    {
        try { return _pipe.Request(new IpcRequest { Cmd = Ipc.CmdStatus }, 4000)?.Status; }
        catch { return null; }
    }

    public void Refresh()
    {
        _root.Children.Clear();
        _root.Children.Add(new TextBlock { Text = "Блокировщик сайтов", FontSize = 20, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 8) });

        var st = Status();
        if (st == null)
        {
            _root.Children.Add(Ui.Label("Служба не отвечает. Убедитесь, что программа установлена и служба «Блокировщик сайтов» запущена.", color: Ui.Accent));
            _root.Children.Add(Ui.Btn("Обновить", (_, _) => Refresh()));
            return;
        }

        if (!st.Configured) BuildSetup(st);
        else BuildMain(st);

        _root.Children.Add(new Separator { Margin = new Thickness(0, 14, 0, 6) });
        _root.Children.Add(Ui.Label($"Версия {st.ServiceVersion}. Блокировка действует только в учётной записи, где настроена программа.", 11, color: Ui.Muted));
    }

    // ---------------- Первый запуск ----------------
    private void BuildSetup(StatusDto st)
    {
        _root.Children.Add(Ui.Label("Первый запуск. Задайте пароль и список сайтов для блокировки.", bold: true));
        _root.Children.Add(Ui.Label("Пароль понадобится, чтобы разблокировать сайты, менять список и удалять программу.", 12, color: Ui.Muted));

        _root.Children.Add(Ui.Label("Пароль:"));
        var p1 = new PasswordBox { Padding = new Thickness(6), Margin = new Thickness(0, 0, 0, 4) };
        _root.Children.Add(p1);
        _root.Children.Add(Ui.Label("Повторите пароль:"));
        var p2 = new PasswordBox { Padding = new Thickness(6), Margin = new Thickness(0, 0, 0, 4) };
        _root.Children.Add(p2);

        _root.Children.Add(Ui.Label("Сайты для блокировки (по одному в строке или через запятую):"));
        var sites = new TextBox { AcceptsReturn = true, MinHeight = 90, TextWrapping = TextWrapping.Wrap, Padding = new Thickness(6),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Text = "" };
        _root.Children.Add(sites);
        _root.Children.Add(Ui.Label("Например: youtube.com, vk.com, instagram.com", 11, color: Ui.Muted));

        var browserBoxes = BrowserChecks(BrowserPolicy.DefaultBrowsers());
        _root.Children.Add(Ui.Label("Браузеры, где блокировать:", bold: true));
        foreach (var cb in browserBoxes.Values) _root.Children.Add(cb);

        var msg = Ui.Label("", color: Ui.Accent);
        _root.Children.Add(Ui.Btn("Включить блокировку", (_, _) =>
        {
            if (p1.Password.Length < 4) { msg.Text = "Пароль должен быть не короче 4 символов."; return; }
            if (p1.Password != p2.Password) { msg.Text = "Пароли не совпадают."; return; }
            var list = Domains.NormalizeList(new[] { sites.Text });
            var browsers = browserBoxes.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToList();
            if (browsers.Count == 0) { msg.Text = "Выберите хотя бы один браузер."; return; }
            var s = Settings.Defaults();
            s.Sites = list; s.Browsers = browsers;
            var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdSetup, Password = p1.Password, Settings = s });
            if (r == null) { msg.Text = "Служба не отвечает."; return; }
            if (!r.Ok) { msg.Text = r.Error; return; }
            Refresh();
        }, primary: true));
        _root.Children.Add(msg);
    }

    private static Dictionary<string, CheckBox> BrowserChecks(List<string> selected)
    {
        var all = BrowserPolicy.DefaultBrowsers();
        var d = new Dictionary<string, CheckBox>();
        foreach (var key in all)
            d[key] = new CheckBox { Content = BrowserPolicy.DisplayName(key), IsChecked = selected.Contains(key), Margin = new Thickness(0, 2, 0, 2), FontSize = 13 };
        return d;
    }

    // ---------------- Основной экран ----------------
    private void BuildMain(StatusDto st)
    {
        string stateText;
        Brush stateColor;
        if (!st.Enabled) { stateText = "Блокировка выключена в настройках."; stateColor = Ui.Muted; }
        else if (st.SitesCount == 0) { stateText = "Список сайтов пуст — ничего не блокируется."; stateColor = Ui.Muted; }
        else if (st.Blocked) { stateText = $"Сайты заблокированы ({st.SitesCount} шт.)."; stateColor = Ui.Accent; }
        else if (st.UntilSession) { stateText = "Разблокировано до конца сеанса (до выхода/перезагрузки)."; stateColor = Ui.Ok; }
        else { stateText = $"Разблокировано до {DateTimeOffset.FromUnixTimeMilliseconds(st.UnlockUntil).ToLocalTime():HH:mm}."; stateColor = Ui.Ok; }
        _root.Children.Add(Ui.Label(stateText, 15, bold: true, color: stateColor));
        if (!st.IsOwner) _root.Children.Add(Ui.Label("Эта учётная запись не настраивала блокировщик. Для изменений нужен пароль.", 12, color: Ui.Muted));

        if (st.Blocked)
            _root.Children.Add(Ui.Btn("Разблокировать (по паролю)", (_, _) => UnlockDialog(st), primary: true));
        else if (st.Enabled && st.SitesCount > 0)
            _root.Children.Add(Ui.Btn("Заблокировать сейчас", (_, _) =>
            {
                var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdLock });
                Refresh();
            }));

        _root.Children.Add(Ui.Btn("Список сайтов и настройки", (_, _) => SettingsDialog(st)));
        _root.Children.Add(Ui.Btn("Изменить пароль", (_, _) => ChangePasswordDialog()));
        _root.Children.Add(Ui.Btn("Разрешить удаление/обновление (15 мин)", (_, _) => MaintenanceDialog()));
        _root.Children.Add(Ui.Btn("История", (_, _) => HistoryDialog()));
    }

    // ---------------- Диалоги ----------------
    private void UnlockDialog(StatusDto st)
    {
        var dlg = Dialog("Разблокировать", out var panel);
        panel.Children.Add(Ui.Label("Пароль:"));
        var pw = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(pw);
        panel.Children.Add(Ui.Label("На сколько разблокировать:"));
        var combo = new ComboBox { Margin = new Thickness(0, 2, 0, 2) };
        var mins = st.Settings.AllowedUnlockMinutes ?? new List<int> { 0, 15, 30, 60 };
        foreach (var m in mins) combo.Items.Add(m == 0 ? "До конца сеанса" : $"{m} минут");
        combo.SelectedIndex = 0;
        panel.Children.Add(combo);
        var msg = Ui.Label("", color: Ui.Accent);
        panel.Children.Add(Ui.Btn("Разблокировать", (_, _) =>
        {
            int minutes = mins[Math.Max(0, combo.SelectedIndex)];
            var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdUnlock, Password = pw.Password, ExtraMinutes = minutes });
            if (r == null) { msg.Text = "Служба не отвечает."; return; }
            if (!r.Ok) { msg.Text = r.Error; return; }
            dlg.Close(); Refresh();
        }, primary: true));
        panel.Children.Add(msg);
        pw.Focus();
        dlg.ShowDialog();
    }

    private void SettingsDialog(StatusDto st)
    {
        var dlg = Dialog("Список сайтов и настройки", out var panel);
        panel.Children.Add(Ui.Label("Пароль для изменения:"));
        var pw = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(pw);

        panel.Children.Add(Ui.Label("Сайты (по одному в строке):"));
        var sites = new TextBox { AcceptsReturn = true, MinHeight = 110, TextWrapping = TextWrapping.Wrap, Padding = new Thickness(6),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Text = string.Join(Environment.NewLine, st.Settings.Sites) };
        panel.Children.Add(sites);

        panel.Children.Add(Ui.Label("Браузеры:", bold: true));
        var boxes = BrowserChecks(st.Settings.Browsers);
        foreach (var cb in boxes.Values) panel.Children.Add(cb);

        var enabled = new CheckBox { Content = "Блокировка включена", IsChecked = st.Settings.Enabled, Margin = new Thickness(0, 6, 0, 2) };
        var closeBrowsers = new CheckBox { Content = "Закрывать браузеры при включении блокировки", IsChecked = st.Settings.CloseBrowsersOnBlock, Margin = new Thickness(0, 2, 0, 2) };
        var firewall = new CheckBox { Content = "Доп. уровень: брандмауэр по IP (экспериментально)", IsChecked = st.Settings.FirewallLayer, Margin = new Thickness(0, 2, 0, 2) };
        panel.Children.Add(enabled); panel.Children.Add(closeBrowsers); panel.Children.Add(firewall);

        var msg = Ui.Label("", color: Ui.Accent);
        panel.Children.Add(Ui.Btn("Сохранить", (_, _) =>
        {
            var s = st.Settings.Clone();
            s.Sites = Domains.NormalizeList(new[] { sites.Text });
            s.Browsers = boxes.Where(kv => kv.Value.IsChecked == true).Select(kv => kv.Key).ToList();
            s.Enabled = enabled.IsChecked == true;
            s.CloseBrowsersOnBlock = closeBrowsers.IsChecked == true;
            s.FirewallLayer = firewall.IsChecked == true;
            if (s.Browsers.Count == 0) { msg.Text = "Выберите хотя бы один браузер."; return; }
            var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdSaveSettings, Password = pw.Password, Settings = s });
            if (r == null) { msg.Text = "Служба не отвечает."; return; }
            if (!r.Ok) { msg.Text = r.Error; return; }
            dlg.Close(); Refresh();
        }, primary: true));
        panel.Children.Add(msg);
        dlg.ShowDialog();
    }

    private void ChangePasswordDialog()
    {
        var dlg = Dialog("Изменить пароль", out var panel);
        panel.Children.Add(Ui.Label("Текущий пароль:"));
        var cur = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(cur);
        panel.Children.Add(Ui.Label("Новый пароль:"));
        var np1 = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(np1);
        panel.Children.Add(Ui.Label("Повторите новый пароль:"));
        var np2 = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(np2);
        var msg = Ui.Label("", color: Ui.Accent);
        panel.Children.Add(Ui.Btn("Сохранить", (_, _) =>
        {
            if (np1.Password.Length < 4) { msg.Text = "Новый пароль должен быть не короче 4 символов."; return; }
            if (np1.Password != np2.Password) { msg.Text = "Новые пароли не совпадают."; return; }
            var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdChangePassword, Password = cur.Password, NewPassword = np1.Password });
            if (r == null) { msg.Text = "Служба не отвечает."; return; }
            if (!r.Ok) { msg.Text = r.Error; return; }
            dlg.Close();
        }, primary: true));
        panel.Children.Add(msg);
        dlg.ShowDialog();
    }

    private void MaintenanceDialog()
    {
        var dlg = Dialog("Разрешить удаление/обновление", out var panel);
        panel.Children.Add(Ui.Label("Введите пароль, чтобы на 15 минут разрешить удаление или обновление программы. После этого запустите «Удалить.cmd» или установку новой версии.", 12));
        panel.Children.Add(Ui.Label("Пароль:"));
        var pw = new PasswordBox { Padding = new Thickness(6) };
        panel.Children.Add(pw);
        var msg = Ui.Label("", color: Ui.Accent);
        panel.Children.Add(Ui.Btn("Разрешить на 15 минут", (_, _) =>
        {
            var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdMaintToken, Password = pw.Password });
            if (r == null) { msg.Text = "Служба не отвечает."; return; }
            if (!r.Ok) { msg.Text = r.Error; return; }
            msg.Foreground = Ui.Ok;
            msg.Text = "Разрешение выдано на 15 минут. Теперь запустите «Удалить.cmd» или установку новой версии.";
        }, primary: true));
        panel.Children.Add(msg);
        dlg.ShowDialog();
    }

    private void HistoryDialog()
    {
        var dlg = Dialog("История", out var panel);
        var r = _pipe.Request(new IpcRequest { Cmd = Ipc.CmdHistory });
        var entries = r?.History?.Entries ?? new List<HistoryEntry>();
        if (entries.Count == 0) panel.Children.Add(Ui.Label("Записей пока нет."));
        foreach (var e in entries.Take(100))
            panel.Children.Add(Ui.Label($"{DateTimeOffset.FromUnixTimeMilliseconds(e.Ts).ToLocalTime():dd.MM HH:mm}  —  {e.Text}", 12));
        dlg.ShowDialog();
    }

    private Window Dialog(string title, out StackPanel panel)
    {
        var w = new Window
        {
            Title = title, Owner = this, Width = 460, SizeToContent = SizeToContent.Height, MaxHeight = 760,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = Ui.Bg, ResizeMode = ResizeMode.NoResize,
        };
        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        panel = new StackPanel { Margin = new Thickness(20) };
        scroll.Content = panel;
        w.Content = scroll;
        return w;
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e);
    }
}
