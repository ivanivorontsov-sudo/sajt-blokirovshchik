using System.Diagnostics;
using SiteBlocker.Core;

namespace SiteBlocker.Service;

/// <summary>
/// Основной цикл службы (раз в секунду). Источник истины для блокировки:
///  * блокировка — per-user: политики браузеров пишутся в куст владельца HKU\&lt;SID&gt; (другие учётки не трогаются);
///  * разблокировка только по паролю (проверяет служба), действует до конца сеанса или заданное время;
///  * самовосстановление: если политики убрали вручную — служба возвращает их в течение секунды;
///  * самозащита службы (DACL, автозапуск, права на папки) и «неостанавливаемость» (кроме режима обслуживания);
///  * обслуживание (удаление/обновление) — только по одноразовому токену, выданному после ввода пароля.
/// </summary>
public sealed class GuardWorker : IDisposable
{
    public static string AppVersion => typeof(GuardWorker).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";

    private readonly string _exe;
    private readonly WinClock _clock = new();
    private readonly AutoResetEvent _wake = new(false);
    private readonly WinRegistry _reg = new();
    private volatile bool _stop;
    private Thread? _thread;
    private PipeServer? _pipe;
    public MaintenanceTokens Tokens { get; }
    public string DataDir { get; }

    private long _lastTamperScan = long.MinValue;
    private long _lastAcceptStop = long.MinValue;
    private long _startedMono;
    private long _lastFirewall = long.MinValue;

    // Применённое состояние блокировки по SID (для обнаружения перехода «разблок → блок»).
    private readonly Dictionary<string, bool> _appliedBlocked = new(StringComparer.OrdinalIgnoreCase);
    private bool _firewallApplied;
    private readonly object _gate = new();

    public long MaintenanceUntil { get; private set; }
    public bool InMaintenance => MaintenanceUntil > _clock.Wall();

    public GuardWorker(string exePath)
    {
        _exe = exePath;
        DataDir = Paths.DataDir;
        Directory.CreateDirectory(DataDir);
        Tokens = new MaintenanceTokens(() => _clock.Wall());
    }

    public void Start()
    {
        _startedMono = _clock.Mono();
        Log.Write($"Служба запущена, версия {AppVersion}, данные: {DataDir}");
        _pipe = new PipeServer(this);
        _pipe.Start();
        _thread = new Thread(Loop) { IsBackground = true, Name = "SiteBlocker.Guard" };
        _thread.Start();
    }

    public void Wake() => _wake.Set();

    public void Stop(bool removePolicies)
    {
        _stop = true; _wake.Set();
        _thread?.Join(5000);
        _pipe?.Stop();
        if (removePolicies)
        {
            try
            {
                var m = DataLayout.LoadMachine(DataDir);
                foreach (var sid in Targets(m)) SafeRemove(sid);
                Firewall.Remove();
            }
            catch (Exception e) { Log.Write("remove on stop: " + e.Message); }
        }
        Log.Write("Служба остановлена");
    }

    private void Loop()
    {
        while (!_stop)
        {
            try { Once(); }
            catch (Exception e) { Log.Write("loop: " + e); }
            _wake.WaitOne(1000);
        }
    }

    public static List<string> Targets(MachineConfig m)
    {
        var list = (m.TargetSids != null && m.TargetSids.Count > 0) ? new List<string>(m.TargetSids) : new List<string>();
        if (!string.IsNullOrEmpty(m.OwnerSid) && !list.Contains(m.OwnerSid, StringComparer.OrdinalIgnoreCase)) list.Insert(0, m.OwnerSid);
        return list.Where(s => !string.IsNullOrEmpty(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void Once()
    {
        ManageUnstoppable();
        if (!InMaintenance) ScanTamperThrottled();

        var machine = DataLayout.LoadMachine(DataDir);
        if (string.IsNullOrEmpty(machine.OwnerSid)) return; // ещё не настроено

        var sessions = Sessions.Enumerate();
        var loggedInSids = new HashSet<string>(sessions.Where(s => s.Sid != null).Select(s => s.Sid!), StringComparer.OrdinalIgnoreCase);
        var owner = machine.OwnerSid;
        bool ownerLoggedIn = loggedInSids.Contains(owner);
        uint ownerLogon = ownerLoggedIn ? sessions.First(s => string.Equals(s.Sid, owner, StringComparison.OrdinalIgnoreCase)).Id : 0u;

        var store = new Store(Paths.UserDataDir(owner));
        var settings = store.LoadSettings();
        var state = store.LoadState();

        // Истекла/недействительна разблокировка — вернуть блокировку.
        if (state.Unlocked && !UnlockLogic.UnlockActive(state, _clock.BootId, ownerLoggedIn, ownerLogon, _clock.Wall()))
        {
            state = UnlockLogic.Locked();
            store.SaveState(state);
            store.Log(HistoryEntry.Lock, "Разблокировка закончилась — блокировка восстановлена", _clock.Wall());
            Log.Write("разблокировка истекла — блокировка восстановлена");
        }

        bool shouldBlock = !InMaintenance && UnlockLogic.ShouldBlock(settings, state, _clock.BootId, ownerLoggedIn, ownerLogon, _clock.Wall());

        var targets = Targets(machine);
        foreach (var sid in targets)
        {
            if (!loggedInSids.Contains(sid)) continue; // куст не загружен — применим, когда войдёт
            try
            {
                if (shouldBlock)
                {
                    var engine = new PolicyEngine(_reg);
                    bool was = _appliedBlocked.TryGetValue(sid, out var b) && b;
                    if (!engine.IsApplied("HKU\\" + sid, settings))
                    {
                        engine.Apply("HKU\\" + sid, settings);
                        foreach (var err in engine.Errors) Log.Write("policy " + DataLayout.SafeSid(sid) + ": " + err);
                    }
                    _appliedBlocked[sid] = true;
                    if (!was && settings.CloseBrowsersOnBlock) CloseBrowsers(sid, sessions, settings);
                }
                else
                {
                    if (!_appliedBlocked.TryGetValue(sid, out var b) || b || new PolicyEngine(_reg).IsAnyPresent("HKU\\" + sid))
                        SafeRemove(sid);
                    _appliedBlocked[sid] = false;
                }
            }
            catch (Exception e) { Log.Write("enforce " + DataLayout.SafeSid(sid) + ": " + e.Message); }
        }

        // Уровень брандмауэра (по SID владельца/целей). Обновляем IP не чаще раза в 5 минут.
        if (settings.FirewallLayer && shouldBlock)
        {
            long m = _clock.Mono();
            if (!_firewallApplied || _lastFirewall == long.MinValue || m - _lastFirewall > 300_000)
            {
                _lastFirewall = m;
                try { Firewall.Apply(targets, settings.Sites); _firewallApplied = true; } catch (Exception e) { Log.Write("firewall apply: " + e.Message); }
            }
        }
        else if (_firewallApplied)
        {
            try { Firewall.Remove(); } catch { }
            _firewallApplied = false;
        }
    }

    private void SafeRemove(string sid)
    {
        if (!sid.StartsWith("S-", StringComparison.OrdinalIgnoreCase)) return;
        try
        {
            var engine = new PolicyEngine(_reg);
            engine.Remove("HKU\\" + sid);
        }
        catch (Exception e) { Log.Write("remove " + DataLayout.SafeSid(sid) + ": " + e.Message); }
    }

    private void CloseBrowsers(string sid, List<Sessions.Info> sessions, Settings settings)
    {
        var sidSessions = sessions.Where(s => string.Equals(s.Sid, sid, StringComparison.OrdinalIgnoreCase)).Select(s => s.Id).ToHashSet();
        if (sidSessions.Count == 0) return;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var b in settings.Browsers)
            if (BrowserPolicy.ProcessNames.TryGetValue(b, out var pn)) foreach (var n in pn) names.Add(n);
        foreach (var name in names)
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    try { if (sidSessions.Contains((uint)p.SessionId)) p.Kill(); } catch { }
                }
            }
        }
        Log.Write($"браузеры закрыты для применения блокировки (пользователь {DataLayout.SafeSid(sid)})");
    }

    private void ManageUnstoppable()
    {
        if (MaintenanceUntil != 0 && !InMaintenance) { MaintenanceUntil = 0; Log.Write("режим обслуживания закончился — защита восстановлена"); _lastTamperScan = long.MinValue; }
        if (!InMaintenance && (_lastAcceptStop == long.MinValue || _clock.Mono() - _lastAcceptStop > 5000) && _clock.Mono() - _startedMono > 3000)
        { _lastAcceptStop = _clock.Mono(); ServiceControl.AcceptStop(false); }
    }

    private void ScanTamperThrottled()
    {
        long m = _clock.Mono();
        if (_lastTamperScan != long.MinValue && m - _lastTamperScan <= 10_000) return;
        _lastTamperScan = m;
        try { foreach (var msg in SelfProtect.CheckAndRepair(_exe)) Log.Write("tamper: " + msg); }
        catch (Exception e) { Log.Write("tamper scan: " + e.Message); }
    }

    // ---------------- Команды от окна (через PipeServer) ----------------

    public StatusDto BuildStatus(string? clientSid)
    {
        var m = DataLayout.LoadMachine(DataDir);
        var owner = m.OwnerSid;
        var st = new StatusDto { ServiceVersion = AppVersion };
        st.Configured = !string.IsNullOrEmpty(owner) && new Store(Paths.UserDataDir(owner)).LoadAuth() != null;
        st.IsOwner = !string.IsNullOrEmpty(owner) && string.Equals(owner, clientSid, StringComparison.OrdinalIgnoreCase);
        st.OwnerName = NameOf(owner);
        if (string.IsNullOrEmpty(owner)) { st.Settings = Settings.Defaults(); return st; }
        var store = new Store(Paths.UserDataDir(owner));
        var settings = store.LoadSettings();
        var state = store.LoadState();
        var sessions = Sessions.Enumerate();
        bool ownerLoggedIn = sessions.Any(s => string.Equals(s.Sid, owner, StringComparison.OrdinalIgnoreCase));
        uint ownerLogon = ownerLoggedIn ? sessions.First(s => string.Equals(s.Sid, owner, StringComparison.OrdinalIgnoreCase)).Id : 0u;
        bool active = UnlockLogic.UnlockActive(state, _clock.BootId, ownerLoggedIn, ownerLogon, _clock.Wall());
        st.Enabled = settings.Enabled;
        st.Settings = settings;
        st.SitesCount = settings.Sites.Count;
        st.Unlocked = active;
        st.UnlockUntil = state.UnlockUntil;
        st.UntilSession = state.UntilSession;
        st.Blocked = settings.Enabled && settings.Sites.Count > 0 && !active;
        return st;
    }

    private static string NameOf(string? sid)
    {
        if (string.IsNullOrEmpty(sid)) return "";
        try { return new System.Security.Principal.SecurityIdentifier(sid).Translate(typeof(System.Security.Principal.NTAccount)).Value; }
        catch { return sid; }
    }

    /// <summary>Первый запуск: задать пароль и список. Клиент становится владельцем. Разрешено один раз.</summary>
    public IpcResponse Setup(IpcRequest r, string clientSid)
    {
        lock (_gate)
        {
            var m = DataLayout.LoadMachine(DataDir);
            if (!string.IsNullOrEmpty(m.OwnerSid))
            {
                var ex = new Store(Paths.UserDataDir(m.OwnerSid)).LoadAuth();
                if (ex != null) return IpcResponse.Fail("Блокировщик уже настроен. Измените настройки через пароль.");
            }
            if (string.IsNullOrWhiteSpace(r.Password) || r.Password!.Length < 4) return IpcResponse.Fail("Задайте пароль не короче 4 символов.");
            var settings = (r.Settings ?? Settings.Defaults()).Normalized();
            var store = new Store(Paths.UserDataDir(clientSid));
            store.SaveAuth(PasswordHash.Create(r.Password!, _clock.Wall()));
            store.SaveSettings(settings);
            store.SaveState(UnlockLogic.Locked());
            m.OwnerSid = clientSid;
            if (m.TargetSids == null || m.TargetSids.Count == 0) m.TargetSids = new() { clientSid };
            if (m.InstalledAt == 0) m.InstalledAt = _clock.Wall();
            m.LastVersion = AppVersion;
            DataLayout.SaveMachine(DataDir, m);
            store.Log(HistoryEntry.Settings, "Блокировщик настроен (пароль и список сайтов заданы)", _clock.Wall());
            Log.Write("настроен; владелец " + DataLayout.SafeSid(clientSid));
            Wake();
            return new IpcResponse { Ok = true, Status = BuildStatus(clientSid) };
        }
    }

    private Store? OwnerStore(out MachineConfig m)
    {
        m = DataLayout.LoadMachine(DataDir);
        if (string.IsNullOrEmpty(m.OwnerSid)) return null;
        return new Store(Paths.UserDataDir(m.OwnerSid));
    }

    private bool VerifyOwner(string? clientSid, Store store, MachineConfig m, string? password, out string? err)
    {
        err = null;
        if (!string.Equals(clientSid, m.OwnerSid, StringComparison.OrdinalIgnoreCase))
        {
            // Пароль всё равно обязателен; владельца определяем по паролю. Разрешаем админу другой учётки с паролем.
        }
        if (!PasswordHash.Verify(store.LoadAuth(), password ?? ""))
        {
            store.Log(HistoryEntry.BadPassword, "Неверный пароль", _clock.Wall());
            err = "Неверный пароль.";
            return false;
        }
        return true;
    }

    public IpcResponse Unlock(IpcRequest r, string? clientSid)
    {
        lock (_gate)
        {
            var store = OwnerStore(out var m);
            if (store == null) return IpcResponse.Fail("Блокировщик не настроен.");
            if (!VerifyOwner(clientSid, store, m, r.Password, out var err)) return IpcResponse.Fail(err!);
            var sessions = Sessions.Enumerate();
            bool ownerLoggedIn = sessions.Any(s => string.Equals(s.Sid, m.OwnerSid, StringComparison.OrdinalIgnoreCase));
            uint ownerLogon = ownerLoggedIn ? sessions.First(s => string.Equals(s.Sid, m.OwnerSid, StringComparison.OrdinalIgnoreCase)).Id : 0u;
            int minutes = r.ExtraMinutes ?? 0;
            var st = UnlockLogic.GrantUnlock(minutes, _clock.BootId, ownerLogon, _clock.Wall());
            store.SaveState(st);
            store.Log(HistoryEntry.Unlock, minutes <= 0 ? "Разблокировано до конца сеанса" : $"Разблокировано на {minutes} мин", _clock.Wall());
            Log.Write("разблокировано (" + (minutes <= 0 ? "до конца сеанса" : minutes + " мин") + ")");
            Wake();
            return new IpcResponse { Ok = true, Status = BuildStatus(clientSid) };
        }
    }

    public IpcResponse Lock(string? clientSid)
    {
        lock (_gate)
        {
            var store = OwnerStore(out _);
            if (store == null) return IpcResponse.Fail("Блокировщик не настроен.");
            store.SaveState(UnlockLogic.Locked());
            store.Log(HistoryEntry.Lock, "Заблокировано вручную", _clock.Wall());
            Wake();
            return new IpcResponse { Ok = true, Status = BuildStatus(clientSid) };
        }
    }

    public IpcResponse ChangePassword(IpcRequest r, string? clientSid)
    {
        lock (_gate)
        {
            var store = OwnerStore(out var m);
            if (store == null) return IpcResponse.Fail("Блокировщик не настроен.");
            if (!VerifyOwner(clientSid, store, m, r.Password, out var err)) return IpcResponse.Fail(err!);
            if (string.IsNullOrWhiteSpace(r.NewPassword) || r.NewPassword!.Length < 4) return IpcResponse.Fail("Новый пароль должен быть не короче 4 символов.");
            store.SaveAuth(PasswordHash.Create(r.NewPassword!, _clock.Wall()));
            store.Log(HistoryEntry.Settings, "Пароль изменён", _clock.Wall());
            return new IpcResponse { Ok = true, Status = BuildStatus(clientSid) };
        }
    }

    public IpcResponse SaveSettings(IpcRequest r, string? clientSid)
    {
        lock (_gate)
        {
            var store = OwnerStore(out var m);
            if (store == null) return IpcResponse.Fail("Блокировщик не настроен.");
            if (!VerifyOwner(clientSid, store, m, r.Password, out var err)) return IpcResponse.Fail(err!);
            if (r.Settings == null) return IpcResponse.Fail("Нет настроек.");
            var ns = r.Settings.Normalized();
            store.SaveSettings(ns);
            store.Log(HistoryEntry.Settings, "Настройки изменены (сайтов: " + ns.Sites.Count + ")", _clock.Wall());
            // Сбросить применённое состояние, чтобы политики перезаписались под новый список.
            foreach (var sid in Targets(m)) { try { SafeRemove(sid); } catch { } _appliedBlocked[sid] = false; }
            _firewallApplied = false;
            Wake();
            return new IpcResponse { Ok = true, Status = BuildStatus(clientSid) };
        }
    }

    public IpcResponse IssueMaintToken(IpcRequest r, string? clientSid)
    {
        lock (_gate)
        {
            var store = OwnerStore(out var m);
            if (store == null) return IpcResponse.Fail("Блокировщик не настроен.");
            if (!VerifyOwner(clientSid, store, m, r.Password, out var err)) return IpcResponse.Fail(err!);
            var tok = Tokens.Issue(MaintenanceTokens.Maintenance);
            try
            {
                // Токен кладём в файл (только после проверки пароля) — установщик/деинсталлятор прочитают его.
                var tf = Path.Combine(DataDir, "maint.token");
                File.WriteAllText(tf, Json.Serialize(new Dictionary<string, object> { ["value"] = tok.Value, ["expiresAt"] = tok.ExpiresAt }));
            }
            catch (Exception e) { Log.Write("write token: " + e.Message); }
            store.Log(HistoryEntry.Settings, "Выдано разрешение на удаление/обновление (15 мин)", _clock.Wall());
            return new IpcResponse { Ok = true, Token = tok.Value, TokenExpiresAt = tok.ExpiresAt };
        }
    }

    public string? BeginMaintenance(string? token, string requester, bool elevated)
    {
        if (!elevated) return "Режим обслуживания включает только установщик от имени администратора.";
        if (string.IsNullOrEmpty(token) || !Tokens.Consume(token!, MaintenanceTokens.Maintenance))
            return "Нет разрешения. Откройте «Блокировщик сайтов», введите пароль и нажмите «Разрешить удаление/обновление» (действует 15 минут).";
        MaintenanceUntil = _clock.Wall() + MaintenanceTokens.DefaultTtlMs;
        Log.Write($"режим обслуживания включён ({requester}) до {DateTimeOffset.FromUnixTimeMilliseconds(MaintenanceUntil).ToLocalTime():HH:mm}");
        // Снять политики и ослабить защиту, чтобы установщик мог заменить файлы.
        try { var m = DataLayout.LoadMachine(DataDir); foreach (var sid in Targets(m)) SafeRemove(sid); Firewall.Remove(); } catch (Exception e) { Log.Write("maint remove: " + e.Message); }
        try { SelfProtect.Relax(_exe); } catch (Exception e) { Log.Write("relax: " + e.Message); }
        ServiceControl.AcceptStop(true);
        return null;
    }

    public HistoryFile History()
    {
        var store = OwnerStore(out _);
        return store?.LoadHistory() ?? new HistoryFile();
    }

    public void Dispose() { _wake.Dispose(); }
}
