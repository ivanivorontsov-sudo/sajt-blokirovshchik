namespace SiteBlocker.Core;

/// <summary>Чистая логика «действует ли сейчас разблокировка» и «нужно ли блокировать». Тестируется без Windows.</summary>
public static class UnlockLogic
{
    /// <summary>
    /// Действует ли разблокировка прямо сейчас.
    ///  * таймер: !UntilSession и now &lt; UnlockUntil;
    ///  * до конца сеанса: UntilSession, тот же BootId, владелец всё ещё в системе и тот же сеанс входа.
    /// </summary>
    public static bool UnlockActive(BlockState st, string bootId, bool ownerLoggedIn, uint currentLogonSession, long nowMs)
    {
        if (st == null || !st.Unlocked) return false;
        if (st.UntilSession)
        {
            if (!string.Equals(st.BootId, bootId, StringComparison.Ordinal)) return false;
            if (!ownerLoggedIn) return false;
            if (st.LogonSession != 0 && currentLogonSession != 0 && st.LogonSession != currentLogonSession) return false;
            return true;
        }
        return nowMs < st.UnlockUntil;
    }

    /// <summary>Нужно ли сейчас держать блокировку (с точки зрения настроек и разблокировки).</summary>
    public static bool ShouldBlock(Settings s, BlockState st, string bootId, bool ownerLoggedIn, uint currentLogonSession, long nowMs)
    {
        if (s == null || !s.Enabled) return false;
        if (s.Sites.Count == 0) return false;
        return !UnlockActive(st, bootId, ownerLoggedIn, currentLogonSession, nowMs);
    }

    /// <summary>Построить состояние разблокировки по запросу (extraMinutes: 0 = до конца сеанса).</summary>
    public static BlockState GrantUnlock(int extraMinutes, string bootId, uint logonSession, long nowMs)
    {
        if (extraMinutes <= 0)
            return new BlockState { Unlocked = true, UntilSession = true, UnlockUntil = 0, BootId = bootId, LogonSession = logonSession };
        return new BlockState { Unlocked = true, UntilSession = false, UnlockUntil = nowMs + extraMinutes * 60_000L, BootId = bootId, LogonSession = logonSession };
    }

    public static BlockState Locked() => new BlockState { Unlocked = false };
}
