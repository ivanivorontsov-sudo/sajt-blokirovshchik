using System.Text.RegularExpressions;

namespace SiteBlocker.Core;

/// <summary>Нормализация доменов и построение фильтров для политик браузеров.</summary>
public static partial class Domains
{
    [GeneratedRegex(@"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)+$")]
    private static partial Regex HostRe();

    /// <summary>
    /// Приводит ввод пользователя к «голому» хосту: убирает схему, www., путь, порт, пробелы, регистр.
    /// Возвращает null, если это не похоже на домен.
    /// </summary>
    public static string? Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var s = raw.Trim().ToLowerInvariant();
        // Удалить схему.
        int sch = s.IndexOf("://", StringComparison.Ordinal);
        if (sch >= 0) s = s[(sch + 3)..];
        // Удалить всё после первого '/', '?', '#'.
        foreach (var c in new[] { '/', '?', '#', '\\' })
        {
            int i = s.IndexOf(c);
            if (i >= 0) s = s[..i];
        }
        // Удалить учётные данные user@host.
        int at = s.IndexOf('@');
        if (at >= 0) s = s[(at + 1)..];
        // Удалить порт.
        int colon = s.IndexOf(':');
        if (colon >= 0) s = s[..colon];
        // Убрать ведущий www.
        while (s.StartsWith("www.", StringComparison.Ordinal)) s = s[4..];
        s = s.Trim('.').Trim();
        if (s.Length == 0 || s.Length > 253) return null;
        if (!HostRe().IsMatch(s)) return null;
        return s;
    }

    public static List<string> NormalizeList(IEnumerable<string>? items)
    {
        var set = new List<string>();
        if (items == null) return set;
        foreach (var it in items)
        {
            // Разрешаем ввод через запятую/перевод строки/пробел.
            foreach (var part in Regex.Split(it ?? "", @"[\s,;]+"))
            {
                var n = Normalize(part);
                if (n != null && !set.Contains(n)) set.Add(n);
            }
        }
        return set;
    }

    /// <summary>
    /// Фильтры для Chromium URLBlocklist. "domain" блокирует domain и все поддомены (включая www).
    /// Добавляем и явный ".domain" на всякий случай не нужно — голый host уже покрывает поддомены.
    /// </summary>
    public static List<string> ChromiumBlocklist(IEnumerable<string> hosts) =>
        hosts.Select(h => h).ToList();

    /// <summary>Паттерны для Firefox WebsiteFilter (match patterns).</summary>
    public static List<string> FirefoxPatterns(IEnumerable<string> hosts)
    {
        var list = new List<string>();
        foreach (var h in hosts)
        {
            list.Add($"*://{h}/*");
            list.Add($"*://*.{h}/*");
        }
        return list;
    }
}
