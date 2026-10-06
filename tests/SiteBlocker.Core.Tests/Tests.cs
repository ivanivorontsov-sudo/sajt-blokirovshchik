using SiteBlocker.Core;
using Xunit;

namespace SiteBlocker.Core.Tests;

public class DomainsTests
{
    [Theory]
    [InlineData("https://www.YouTube.com/watch?v=1", "youtube.com")]
    [InlineData("  VK.COM/feed  ", "vk.com")]
    [InlineData("http://sub.example.co.uk", "sub.example.co.uk")]
    [InlineData("user:pass@site.org:8080/path", "site.org")]
    [InlineData("instagram.com.", "instagram.com")]
    public void Normalizes(string input, string expected) => Assert.Equal(expected, Domains.Normalize(input));

    [Theory]
    [InlineData("")]
    [InlineData("not a domain")]
    [InlineData("http://")]
    [InlineData("localhost")]
    public void RejectsJunk(string input) => Assert.Null(Domains.Normalize(input));

    [Fact]
    public void ListDedupesAndSplits()
    {
        var r = Domains.NormalizeList(new[] { "youtube.com, vk.com\nYOUTUBE.com", "  ok.ru ; mail.ru" });
        Assert.Equal(new[] { "youtube.com", "vk.com", "ok.ru", "mail.ru" }, r);
    }

    [Fact]
    public void FirefoxPatternsCoverSubdomains()
    {
        var p = Domains.FirefoxPatterns(new[] { "youtube.com" });
        Assert.Contains("*://youtube.com/*", p);
        Assert.Contains("*://*.youtube.com/*", p);
    }
}

public class PasswordHashTests
{
    [Fact]
    public void VerifiesCorrectRejectsWrong()
    {
        var a = PasswordHash.Create("Secret123", 1000);
        Assert.True(PasswordHash.Verify(a, "Secret123"));
        Assert.False(PasswordHash.Verify(a, "secret123"));
        Assert.False(PasswordHash.Verify(a, ""));
        Assert.False(PasswordHash.Verify(null, "x"));
    }

    [Fact]
    public void NoPlaintextStored()
    {
        var a = PasswordHash.Create("MyPassw0rd", 1000);
        var json = Json.Serialize(a);
        Assert.DoesNotContain("MyPassw0rd", json);
        Assert.True(a.Iterations >= 100_000);
    }

    [Fact]
    public void SaltIsRandom()
    {
        var a = PasswordHash.Create("same", 1);
        var b = PasswordHash.Create("same", 1);
        Assert.NotEqual(a.Salt, b.Salt);
        Assert.NotEqual(a.Hash, b.Hash);
    }
}

public class UnlockLogicTests
{
    private static Settings S(params string[] sites) => new Settings { Enabled = true, Sites = sites.ToList(), Browsers = BrowserPolicy.DefaultBrowsers() };

    [Fact]
    public void BlocksWhenLockedAndSitesPresent()
    {
        Assert.True(UnlockLogic.ShouldBlock(S("a.com"), UnlockLogic.Locked(), "b1", true, 1, 1000));
    }

    [Fact]
    public void NoBlockWhenNoSites()
    {
        Assert.False(UnlockLogic.ShouldBlock(S(), UnlockLogic.Locked(), "b1", true, 1, 1000));
    }

    [Fact]
    public void NoBlockWhenDisabled()
    {
        var s = S("a.com"); s.Enabled = false;
        Assert.False(UnlockLogic.ShouldBlock(s, UnlockLogic.Locked(), "b1", true, 1, 1000));
    }

    [Fact]
    public void TimedUnlockExpires()
    {
        var st = UnlockLogic.GrantUnlock(15, "b1", 1, 1000);
        Assert.True(UnlockLogic.UnlockActive(st, "b1", true, 1, 1000 + 10 * 60_000));
        Assert.False(UnlockLogic.UnlockActive(st, "b1", true, 1, 1000 + 20 * 60_000));
    }

    [Fact]
    public void SessionUnlockEndsOnReboot()
    {
        var st = UnlockLogic.GrantUnlock(0, "b1", 7, 1000);
        Assert.True(UnlockLogic.UnlockActive(st, "b1", true, 7, 99999));
        Assert.False(UnlockLogic.UnlockActive(st, "b2", true, 7, 99999)); // другой BootId = перезагрузка
    }

    [Fact]
    public void SessionUnlockEndsOnLogoff()
    {
        var st = UnlockLogic.GrantUnlock(0, "b1", 7, 1000);
        Assert.False(UnlockLogic.UnlockActive(st, "b1", false, 0, 99999)); // владелец не в системе
    }

    [Fact]
    public void SessionUnlockEndsOnDifferentSession()
    {
        var st = UnlockLogic.GrantUnlock(0, "b1", 7, 1000);
        Assert.False(UnlockLogic.UnlockActive(st, "b1", true, 9, 99999)); // другой сеанс входа
    }
}

public class PolicyEngineTests
{
    private const string Hive = "HKU\\S-1-5-21-1-2-3-1001";
    private static Settings S() => new Settings { Enabled = true, Sites = new() { "youtube.com", "vk.com" }, Browsers = new() { "edge", "vivaldi", "firefox" } };

    [Fact]
    public void ApplyWritesBlocklistAndDoHOff()
    {
        var reg = new FakeRegistry();
        var e = new PolicyEngine(reg);
        e.Apply(Hive, S());
        var edge = Hive + "\\Software\\Policies\\Microsoft\\Edge";
        Assert.Equal(new[] { "youtube.com", "vk.com" }, reg.GetStringList(edge + "\\URLBlocklist"));
        Assert.Equal(new[] { "youtube.com", "vk.com" }, reg.GetStringList(edge + "\\IncognitoModeUrlBlocklist"));
        Assert.Equal("off", reg.GetString(edge, "DnsOverHttpsMode"));
        Assert.Equal(0, reg.GetDword(edge, "BuiltInDnsClientEnabled"));
        var viv = Hive + "\\Software\\Policies\\Vivaldi\\URLBlocklist";
        Assert.Equal(new[] { "youtube.com", "vk.com" }, reg.GetStringList(viv));
        var ff = Hive + "\\Software\\Policies\\Mozilla\\Firefox\\WebsiteFilter\\Block";
        Assert.Contains("*://youtube.com/*", reg.GetStringList(ff));
    }

    [Fact]
    public void IsAppliedTrueAfterApplyFalseAfterRemove()
    {
        var reg = new FakeRegistry();
        var e = new PolicyEngine(reg);
        var s = S();
        Assert.False(e.IsApplied(Hive, s));
        e.Apply(Hive, s);
        Assert.True(e.IsApplied(Hive, s));
        Assert.True(e.IsAnyPresent(Hive));
        e.Remove(Hive);
        Assert.False(e.IsApplied(Hive, s));
        Assert.False(e.IsAnyPresent(Hive));
    }

    [Fact]
    public void IsAppliedFalseWhenListChanged()
    {
        var reg = new FakeRegistry();
        var e = new PolicyEngine(reg);
        var s = S();
        e.Apply(Hive, s);
        s.Sites.Add("ok.ru");
        Assert.False(e.IsApplied(Hive, s)); // список поменялся → служба перезапишет
    }

    [Fact]
    public void RemoveOnlyTouchesTargetHive()
    {
        var reg = new FakeRegistry();
        var e = new PolicyEngine(reg);
        var other = "HKU\\S-1-5-21-9-9-9-500";
        e.Apply(Hive, S());
        e.Apply(other, S());
        e.Remove(Hive);
        Assert.False(e.IsAnyPresent(Hive));
        Assert.True(e.IsAnyPresent(other)); // чужая учётка не затронута
    }
}


public class MaintenanceGateTests
{
    [Fact]
    public void NotElevatedAlwaysRefused()
    {
        Assert.Equal(MaintGate.NotElevated, MaintenanceGate.Decide(elevated: false, configured: false, hasValidToken: false));
        Assert.Equal(MaintGate.NotElevated, MaintenanceGate.Decide(elevated: false, configured: true, hasValidToken: true));
    }

    [Fact]
    public void UnconfiguredAllowedWithoutToken()
    {
        // Сломанная/пустая установка всегда удаляема администратором (пароль ещё не задан).
        Assert.Equal(MaintGate.Allow, MaintenanceGate.Decide(elevated: true, configured: false, hasValidToken: false));
    }

    [Fact]
    public void ConfiguredNeedsToken()
    {
        Assert.Equal(MaintGate.NeedToken, MaintenanceGate.Decide(elevated: true, configured: true, hasValidToken: false));
        Assert.Equal(MaintGate.Allow, MaintenanceGate.Decide(elevated: true, configured: true, hasValidToken: true));
    }
}
