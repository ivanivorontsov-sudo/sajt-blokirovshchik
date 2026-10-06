using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace SiteBlocker.Service;

/// <summary>
/// Самозащита службы (не «зловред»: без руткитов, без сокрытия процесса, Safe Mode и аварийное восстановление
/// остаются рабочими). Служба периодически проверяет и чинит:
///  * ключ службы в реестре (ImagePath, Start=Auto) и её DACL (стоп/пауза/переконфигурация — только SYSTEM);
///  * failure actions (перезапуск при сбое);
///  * записи автозапуска окна (HKLM Run для всех пользователей);
///  * ACL на папке программы и %ProgramData%\SiteBlocker (SYSTEM — полный, Администраторы/Пользователи — чтение/выполнение).
/// Возвращает список того, что пришлось восстановить (для журнала и вкладки «История»).
/// </summary>
public static class SelfProtect
{
    // DACL службы: SYSTEM — полный; Администраторы — только запрос/чтение статуса и запуск (без stop/pause/config/delete);
    // Интерактивные/служебные — запрос статуса. SACL не задаём (sdset с S: требует SeSecurityPrivilege).
    public const string ServiceSddl =
        "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPRC;;;BA)(A;;CCLCSWRC;;;IU)(A;;CCLCSWRC;;;SU)";

    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunName = "SiteBlocker";

    /// <summary>Установленная копия (Program Files\SiteBlocker)? Отладочный запуск из другой папки ничего не трогает.</summary>
    public static bool IsInstalledCopy(string exePath)
    {
        var want = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SiteBlocker");
        return string.Equals(Path.GetDirectoryName(Path.GetFullPath(exePath))?.TrimEnd('\\'), want.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }

    public static IEnumerable<string> CheckAndRepair(string exePath)
    {
        var issues = new List<string>();
        if (!IsInstalledCopy(exePath)) return issues;
        string installDir = Path.GetDirectoryName(exePath) ?? "";

        // 1. Автозапуск окна для всех пользователей (HKLM Run).
        try
        {
            string want = $"\"{exePath}\" --agent";
            using var run = Registry.LocalMachine.OpenSubKey(RunKey, true) ?? Registry.LocalMachine.CreateSubKey(RunKey, true);
            var cur = run!.GetValue(RunName) as string;
            if (!string.Equals(cur, want, StringComparison.OrdinalIgnoreCase))
            {
                run.SetValue(RunName, want, RegistryValueKind.String);
                issues.Add("восстановлен автозапуск окна (HKLM\\...\\Run\\SiteBlocker)");
            }
        }
        catch (Exception e) { Log.Write("selfprotect run: " + e.Message); }

        // 2. Ключ службы: ImagePath и Start=Auto.
        try
        {
            using var svc = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{Paths.ServiceName}", true);
            if (svc != null)
            {
                string want = $"\"{exePath}\" --service";
                if (svc.GetValue("ImagePath") as string is string ip && !string.Equals(ip, want, StringComparison.OrdinalIgnoreCase))
                { svc.SetValue("ImagePath", want, RegistryValueKind.ExpandString); issues.Add("восстановлен путь службы (ImagePath)"); }
                if (svc.GetValue("Start") is int st && st != 2)
                { svc.SetValue("Start", 2, RegistryValueKind.DWord); issues.Add("восстановлен автозапуск службы (Start=Auto)"); }
            }
        }
        catch (Exception e) { Log.Write("selfprotect svc reg: " + e.Message); }

        // 3. DACL и failure actions службы через sc.exe (идемпотентно — задаём всегда при расхождении не проверяем, sc сам не шумит).
        try
        {
            string cur = Sc("sdshow", Paths.ServiceName).Trim();
            // Ужесточено, если у Администраторов ровно ограниченная запись (без SD/DC/WD/WO/WP/DT/PAUSE).
            if (cur.Contains("D:") && !cur.Contains("(A;;CCLCSWRPRC;;;BA)"))
            {
                Sc("sdset", Paths.ServiceName, ServiceSddl);
                issues.Add("восстановлен DACL службы (остановка/переконфигурация — только SYSTEM)");
            }
        }
        catch (Exception e) { Log.Write("selfprotect sdset: " + e.Message); }

        // 3а. Failure actions (перезапуск при сбое). Проверяем по реестру (вывод sc.exe локализован).
        try
        {
            using var svc = Registry.LocalMachine.OpenSubKey(ServiceKeyPath);
            if (svc != null && svc.GetValue("FailureActions") == null)
            {
                Sc("failure", Paths.ServiceName, "reset=", "86400", "actions=", "restart/1000/restart/1000/restart/5000");
                Sc("failureflag", Paths.ServiceName, "1");
                issues.Add("восстановлен перезапуск службы при сбое");
            }
        }
        catch (Exception e) { Log.Write("selfprotect failure actions: " + e.Message); }

        // 3б. Ключ службы в реестре: Администраторы — только чтение (владелец остаётся «Администраторы»,
        //     поэтому аварийное восстановление может вернуть себе права без особых привилегий — это лишь барьер).
        try { if (HardenServiceKey()) issues.Add("восстановлены права на ключ службы в реестре"); }
        catch (Exception e) { Log.Write("selfprotect svc key acl: " + e.Message); }

        // 4. ACL каталога данных и программы (SYSTEM полный, Администраторы/Пользователи — чтение/выполнение).
        foreach (var dir in new[] { Paths.DataDir, installDir })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try { if (HardenDir(dir)) issues.Add("восстановлены права доступа: " + dir); }
            catch (Exception e) { Log.Write("selfprotect acl " + dir + ": " + e.Message); }
        }

        return issues;
    }

    private static string ServiceKeyPath => $@"SYSTEM\CurrentControlSet\Services\{Paths.ServiceName}";

    public static bool HardenServiceKey()
    {
        using var k = Registry.LocalMachine.OpenSubKey(ServiceKeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.ReadPermissions | RegistryRights.TakeOwnership);
        if (k == null) return false;
        var sec = k.GetAccessControl();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        bool adminCanWrite = false;
        foreach (RegistryAccessRule r in sec.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (r.IdentityReference.Equals(admins) && r.AccessControlType == AccessControlType.Allow && (r.RegistryRights & (RegistryRights.SetValue | RegistryRights.Delete | RegistryRights.CreateSubKey)) != 0)
                adminCanWrite = true;
        if (!adminCanWrite) return false;
        sec.SetAccessRuleProtection(true, false);
        foreach (RegistryAccessRule r in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<RegistryAccessRule>().ToList()) sec.RemoveAccessRule(r);
        var inh = InheritanceFlags.ContainerInherit;
        sec.AddAccessRule(new RegistryAccessRule(system, RegistryRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new RegistryAccessRule(admins, RegistryRights.ReadKey, inh, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new RegistryAccessRule(users, RegistryRights.ReadKey, inh, PropagationFlags.None, AccessControlType.Allow));
        try { sec.SetOwner(admins); } catch { }
        k.SetAccessControl(sec);
        return true;
    }

    private static void RelaxServiceKey()
    {
        using var k = Registry.LocalMachine.OpenSubKey(ServiceKeyPath, RegistryKeyPermissionCheck.ReadWriteSubTree,
            RegistryRights.ReadKey | RegistryRights.ChangePermissions | RegistryRights.ReadPermissions);
        if (k == null) return;
        var sec = k.GetAccessControl();
        sec.AddAccessRule(new RegistryAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), RegistryRights.FullControl,
            InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow));
        k.SetAccessControl(sec);
    }

    /// <summary>SYSTEM/CreatorOwner — полный; Администраторы и Пользователи — только чтение/выполнение. Возвращает true, если ACL менялся.</summary>
    public static bool HardenDir(string dir)
    {
        var di = new DirectoryInfo(dir);
        var sec = di.GetAccessControl();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        var inh = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        // Признак «уже ужесточено»: у Администраторов НЕТ FullControl Allow.
        bool alreadyHard = false;
        var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
        bool adminHasFull = false;
        foreach (FileSystemAccessRule r in rules)
            if (r.IdentityReference.Equals(admins) && r.AccessControlType == AccessControlType.Allow && r.FileSystemRights.HasFlag(FileSystemRights.FullControl))
                adminHasFull = true;
        alreadyHard = !adminHasFull;
        if (alreadyHard) return false;

        sec.SetAccessRuleProtection(true, false); // убрать наследование, не копировать
        foreach (FileSystemAccessRule r in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList())
            sec.RemoveAccessRule(r);
        sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.ReadAndExecute, inh, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute, inh, PropagationFlags.None, AccessControlType.Allow));
        // Владелец — «Администраторы»: вернуть себе запись админ может (владелец меняет ACL без особых привилегий),
        // но только осознанно — это барьер, а не замок. Аварийное восстановление так работает гарантированно.
        try { sec.SetOwner(admins); } catch { }
        di.SetAccessControl(sec);
        return true;
    }

    /// <summary>Режим обслуживания: ослабить DACL службы и ACL каталогов, чтобы установщик/деинсталлятор (админ) мог заменить файлы.</summary>
    public static void Relax(string exePath)
    {
        if (!IsInstalledCopy(exePath)) return;
        try { Sc("sdset", Paths.ServiceName, "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"); }
        catch (Exception e) { Log.Write("relax sdset: " + e.Message); }
        try { RelaxServiceKey(); } catch (Exception e) { Log.Write("relax svc key: " + e.Message); }
        string installDir = Path.GetDirectoryName(exePath) ?? "";
        foreach (var dir in new[] { Paths.DataDir, installDir })
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
            try
            {
                var di = new DirectoryInfo(dir);
                var sec = di.GetAccessControl();
                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                var inh = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, inh, PropagationFlags.None, AccessControlType.Allow));
                di.SetAccessControl(sec);
            }
            catch (Exception e) { Log.Write("relax acl " + dir + ": " + e.Message); }
        }
    }

    private static string Sc(params string[] args)
    {
        var psi = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit(5000);
        return o;
    }
}
