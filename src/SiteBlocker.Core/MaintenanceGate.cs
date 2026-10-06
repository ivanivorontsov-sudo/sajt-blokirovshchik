namespace SiteBlocker.Core;

public enum MaintGate
{
    Allow,        // включить режим обслуживания
    NotElevated,  // не администратор
    NeedToken,    // настроено, но нет действительного разрешения (пароль)
}

/// <summary>
/// Чистое правило допуска к обслуживанию (удаление/обновление). Вынесено отдельно для тестирования.
/// Ключевое: если блокировщик ещё НЕ настроен (нет пароля/владельца), обслуживание разрешено без токена —
/// чтобы сломанную или пустую установку всегда можно было удалить/обновить.
/// </summary>
public static class MaintenanceGate
{
    public static MaintGate Decide(bool elevated, bool configured, bool hasValidToken)
    {
        if (!elevated) return MaintGate.NotElevated;
        if (!configured) return MaintGate.Allow;
        return hasValidToken ? MaintGate.Allow : MaintGate.NeedToken;
    }
}
