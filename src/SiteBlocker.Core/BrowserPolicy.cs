namespace SiteBlocker.Core;

/// <summary>
/// Карта семейств браузеров и их путей политик (относительно Software\Policies), а также движок,
/// который применяет/снимает блокировку в кусте конкретного пользователя (HKU\&lt;SID&gt;).
/// Политики — per-user (в HKCU/HKU), поэтому затрагивают ТОЛЬКО учётку владельца, а не других пользователей ПК.
/// </summary>
public static class BrowserPolicy
{
    /// <summary>Chromium-семейства: ключ настройки → подпуть под Software\Policies.</summary>
    public static readonly IReadOnlyDictionary<string, string> ChromiumVendors = new Dictionary<string, string>
    {
        ["edge"] = @"Microsoft\Edge",
        ["chrome"] = @"Google\Chrome",
        ["chromium"] = @"Chromium",
        ["vivaldi"] = @"Vivaldi",
        ["brave"] = @"BraveSoftware\Brave",
        ["yandex"] = @"YandexBrowser",
        ["opera"] = @"Opera Software\Opera",
    };
    public const string FirefoxKey = "firefox";
    public const string FirefoxPath = @"Mozilla\Firefox";

    public static List<string> DefaultBrowsers()
    {
        var l = ChromiumVendors.Keys.ToList();
        l.Add(FirefoxKey);
        return l;
    }

    /// <summary>Человекочитаемые названия для UI.</summary>
    public static string DisplayName(string key) => key switch
    {
        "edge" => "Microsoft Edge",
        "chrome" => "Google Chrome",
        "chromium" => "Chromium",
        "vivaldi" => "Vivaldi",
        "brave" => "Brave",
        "yandex" => "Яндекс Браузер",
        "opera" => "Opera",
        "firefox" => "Mozilla Firefox",
        _ => key,
    };

    /// <summary>Имена процессов браузеров (для закрытия при включении блокировки).</summary>
    public static readonly IReadOnlyDictionary<string, string[]> ProcessNames = new Dictionary<string, string[]>
    {
        ["edge"] = new[] { "msedge" },
        ["chrome"] = new[] { "chrome" },
        ["chromium"] = new[] { "chrome", "chromium" },
        ["vivaldi"] = new[] { "vivaldi" },
        ["brave"] = new[] { "brave" },
        ["yandex"] = new[] { "browser", "yandex" },
        ["opera"] = new[] { "opera" },
        ["firefox"] = new[] { "firefox" },
    };
}

/// <summary>
/// Применение/снятие политик блокировки в кусте пользователя. hivePrefix — например "HKU\S-1-5-21-...".
/// Всё тестируемо через IRegistry.
/// </summary>
public sealed class PolicyEngine
{
    private readonly IRegistry _reg;
    public List<string> Errors { get; } = new();

    public PolicyEngine(IRegistry reg) { _reg = reg; }

    private static string PoliciesRoot(string hivePrefix) => hivePrefix.TrimEnd('\\') + @"\Software\Policies";

    /// <summary>Применить блокировку указанных хостов для выбранных браузеров в кусте пользователя.</summary>
    public void Apply(string hivePrefix, Settings s)
    {
        var hosts = s.Sites;
        string root = PoliciesRoot(hivePrefix);
        var chromiumList = Domains.ChromiumBlocklist(hosts);
        foreach (var key in s.Browsers)
        {
            try
            {
                if (BrowserPolicy.ChromiumVendors.TryGetValue(key, out var sub))
                {
                    string vp = root + "\\" + sub;
                    _reg.SetStringList(vp + @"\URLBlocklist", chromiumList);
                    _reg.SetStringList(vp + @"\IncognitoModeUrlBlocklist", chromiumList);
                    _reg.SetString(vp, "DnsOverHttpsMode", "off");
                    _reg.SetDword(vp, "BuiltInDnsClientEnabled", 0);
                }
                else if (key == BrowserPolicy.FirefoxKey)
                {
                    string vp = root + "\\" + BrowserPolicy.FirefoxPath;
                    _reg.SetStringList(vp + @"\WebsiteFilter\Block", Domains.FirefoxPatterns(hosts));
                    _reg.SetDword(vp + @"\DNSOverHTTPS", "Enabled", 0);
                    _reg.SetDword(vp + @"\DNSOverHTTPS", "Locked", 1);
                }
            }
            catch (Exception e) { Errors.Add($"{key}: {e.Message}"); }
        }
    }

    /// <summary>Снять все наши политики блокировки (во всех известных браузерах, не только выбранных).</summary>
    public void Remove(string hivePrefix)
    {
        string root = PoliciesRoot(hivePrefix);
        foreach (var sub in BrowserPolicy.ChromiumVendors.Values)
        {
            string vp = root + "\\" + sub;
            try
            {
                _reg.DeleteKeyTree(vp + @"\URLBlocklist");
                _reg.DeleteKeyTree(vp + @"\IncognitoModeUrlBlocklist");
                _reg.DeleteValue(vp, "DnsOverHttpsMode");
                _reg.DeleteValue(vp, "BuiltInDnsClientEnabled");
            }
            catch (Exception e) { Errors.Add("remove " + sub + ": " + e.Message); }
        }
        try
        {
            string vp = root + "\\" + BrowserPolicy.FirefoxPath;
            _reg.DeleteKeyTree(vp + @"\WebsiteFilter");
            _reg.DeleteKeyTree(vp + @"\DNSOverHTTPS");
        }
        catch (Exception e) { Errors.Add("remove firefox: " + e.Message); }
    }

    /// <summary>Присутствует ли хоть какая-то наша политика блокировки в кусте (чтобы знать, нужно ли снимать).</summary>
    public bool IsAnyPresent(string hivePrefix)
    {
        string root = PoliciesRoot(hivePrefix);
        foreach (var sub in BrowserPolicy.ChromiumVendors.Values)
        {
            string vp = root + "\\" + sub;
            if (_reg.KeyExists(vp + @"\URLBlocklist")) return true;
            if (_reg.GetString(vp, "DnsOverHttpsMode") != null) return true;
        }
        string fp = root + "\\" + BrowserPolicy.FirefoxPath;
        if (_reg.KeyExists(fp + @"\WebsiteFilter")) return true;
        return false;
    }

    /// <summary>Проверить, что политики на месте и совпадают с ожидаемыми (для самовосстановления).</summary>
    public bool IsApplied(string hivePrefix, Settings s)
    {
        string root = PoliciesRoot(hivePrefix);
        var expect = Domains.ChromiumBlocklist(s.Sites);
        foreach (var key in s.Browsers)
        {
            if (BrowserPolicy.ChromiumVendors.TryGetValue(key, out var sub))
            {
                string vp = root + "\\" + sub;
                var cur = _reg.GetStringList(vp + @"\URLBlocklist");
                if (!cur.SequenceEqual(expect)) return false;
                if (!string.Equals(_reg.GetString(vp, "DnsOverHttpsMode"), "off", StringComparison.OrdinalIgnoreCase)) return false;
            }
            else if (key == BrowserPolicy.FirefoxKey)
            {
                string vp = root + "\\" + BrowserPolicy.FirefoxPath;
                var cur = _reg.GetStringList(vp + @"\WebsiteFilter\Block");
                if (!cur.SequenceEqual(Domains.FirefoxPatterns(s.Sites))) return false;
            }
        }
        return true;
    }
}
