namespace SiteBlocker.Core;

/// <summary>
/// Абстракция реестра Windows (на Windows — Microsoft.Win32.Registry; в тестах — словарь).
/// Ключ — полный путь вида "HKU\S-1-5-21-...\Software\Policies\...". Поддерживаются скалярные значения
/// и «списковые» подключи Chromium (значения "1","2",... под отдельным подключом).
/// </summary>
public interface IRegistry
{
    int? GetDword(string key, string name);
    void SetDword(string key, string name, int value);
    string? GetString(string key, string name);
    void SetString(string key, string name, string value);
    void DeleteValue(string key, string name);

    /// <summary>Значения-строки "1","2",... под подключом listKey (в порядке номеров). Пусто, если ключа нет.</summary>
    IReadOnlyList<string> GetStringList(string listKey);
    /// <summary>Полностью переписать списковый подключ значениями "1".."N".</summary>
    void SetStringList(string listKey, IReadOnlyList<string> items);

    bool KeyExists(string key);
    /// <summary>Удалить подключ со всем содержимым (рекурсивно). Отсутствующий — молча.</summary>
    void DeleteKeyTree(string key);
}
