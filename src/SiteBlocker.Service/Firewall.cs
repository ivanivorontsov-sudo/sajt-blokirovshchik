using System.Diagnostics;
using System.Net;
using System.Text;

namespace SiteBlocker.Service;

/// <summary>
/// Дополнительный (экспериментальный) уровень: правила брандмауэра Windows, привязанные к SID владельца
/// (-LocalUser), блокирующие исходящие соединения к IP-адресам заблокированных доменов. Это per-user уровень
/// на уровне ОС: работает в любой программе и не зависит от DoH. Слабое место — у крупных сайтов (CDN) IP меняются
/// и общие, поэтому это лишь вторая линия; основная блокировка — политики браузеров. По умолчанию выключен.
/// </summary>
public static class Firewall
{
    public const string Group = "SiteBlocker";

    /// <summary>Пересоздать правила блокировки для владельца. hosts — список доменов.</summary>
    public static void Apply(IReadOnlyList<string> sids, IReadOnlyList<string> hosts)
    {
        Remove();
        if (hosts.Count == 0 || sids.Count == 0) return;
        var ips = new List<string>();
        foreach (var h in hosts)
        {
            foreach (var cand in new[] { h, "www." + h })
            {
                try
                {
                    foreach (var a in Dns.GetHostAddresses(cand))
                    {
                        var s = a.ToString();
                        if (!ips.Contains(s)) ips.Add(s);
                    }
                }
                catch { }
            }
        }
        if (ips.Count == 0) return;
        string sddl = "D:" + string.Concat(sids.Select(x => $"(A;;CC;;;{x})"));
        string remote = string.Join(",", ips.Take(900).Select(x => "'" + x + "'"));
        string ps =
            $"New-NetFirewallRule -DisplayName 'SiteBlocker block' -Group '{Group}' -Direction Outbound -Action Block " +
            $"-RemoteAddress @({remote}) -LocalUser \"{sddl}\" -Profile Any | Out-Null";
        RunPowerShell(ps);
    }

    public static void Remove()
    {
        RunPowerShell($"Remove-NetFirewallRule -Group '{Group}' -ErrorAction SilentlyContinue");
    }

    private static void RunPowerShell(string script)
    {
        try
        {
            var psi = new ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-ExecutionPolicy"); psi.ArgumentList.Add("Bypass");
            psi.ArgumentList.Add("-Command"); psi.ArgumentList.Add(script);
            using var p = Process.Start(psi);
            if (p == null) return;
            p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
        }
        catch (Exception e) { Log.Write("firewall: " + e.Message); }
    }
}
