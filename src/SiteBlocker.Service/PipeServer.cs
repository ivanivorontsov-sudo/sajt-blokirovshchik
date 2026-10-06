using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using SiteBlocker.Core;

namespace SiteBlocker.Service;

/// <summary>
/// Сервер \\.\pipe\SiteBlocker.v1. ACL: SYSTEM и Администраторы — полный доступ, INTERACTIVE — чтение/запись,
/// доступ по сети запрещён. Все решения (пароль, разблокировка, обслуживание) принимает служба.
/// </summary>
public sealed class PipeServer
{
    private readonly GuardWorker _w;
    private readonly CancellationTokenSource _cts = new();

    public PipeServer(GuardWorker w) { _w = w; }
    public void Start() { for (int i = 0; i < 4; i++) _ = Task.Run(AcceptLoop); }
    public void Stop() { _cts.Cancel(); }

    public static PipeSecurity Security()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return ps;
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = NamedPipeServerStreamAcl.Create(Ipc.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 64 * 1024, 64 * 1024, Security());
                await server.WaitForConnectionAsync(_cts.Token);
                var s = server; server = null;
                _ = Task.Run(() => Handle(s));
            }
            catch (OperationCanceledException) { server?.Dispose(); return; }
            catch (Exception e) { server?.Dispose(); Log.Write("pipe accept: " + e.Message); await Task.Delay(500); }
        }
    }

    private async Task Handle(NamedPipeServerStream s)
    {
        using (s)
        {
            uint session = 0; bool sessionKnown = false;
            try { sessionKnown = Native.GetNamedPipeClientSessionId(s.SafePipeHandle.DangerousGetHandle(), out session); } catch { }
            string? clientSid = null; bool clientElevated = false; bool identified = false;
            var reader = new StreamReader(s, new UTF8Encoding(false));
            var writer = new StreamWriter(s, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
            try
            {
                while (s.IsConnected && !_cts.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(_cts.Token);
                    if (line == null) break;
                    if (!identified)
                    {
                        identified = true;
                        try
                        {
                            s.RunAsClient(() =>
                            {
                                try
                                {
                                    using var wi = WindowsIdentity.GetCurrent(true) ?? WindowsIdentity.GetCurrent();
                                    clientSid = wi.User?.Value;
                                    clientElevated = new WindowsPrincipal(wi).IsInRole(WindowsBuiltInRole.Administrator);
                                }
                                catch { }
                            });
                        }
                        catch (Exception e) { Log.Write("pipe impersonation: " + e.Message); }
                        if (clientSid == null && sessionKnown) clientSid = Sessions.UserSid(session);
                    }
                    IpcResponse resp;
                    try { resp = Dispatch(Json.Deserialize<IpcRequest>(line) ?? new IpcRequest(), clientSid, clientElevated); }
                    catch (Exception e) { resp = IpcResponse.Fail(e.Message); }
                    await writer.WriteLineAsync(Json.Serialize(resp, false));
                }
            }
            catch (Exception) { }
        }
    }

    private IpcResponse Dispatch(IpcRequest r, string? clientSid, bool clientElevated)
    {
        switch (r.Cmd)
        {
            case Ipc.CmdStatus:
                return new IpcResponse { Ok = true, Status = _w.BuildStatus(clientSid) };
            case Ipc.CmdSetup:
                if (string.IsNullOrEmpty(clientSid)) return IpcResponse.Fail("Не удалось определить пользователя.");
                return _w.Setup(r, clientSid!);
            case Ipc.CmdUnlock:
                return _w.Unlock(r, clientSid);
            case Ipc.CmdLock:
                return _w.Lock(clientSid);
            case Ipc.CmdChangePassword:
                return _w.ChangePassword(r, clientSid);
            case Ipc.CmdSaveSettings:
                return _w.SaveSettings(r, clientSid);
            case Ipc.CmdMaintToken:
                return _w.IssueMaintToken(r, clientSid);
            case Ipc.CmdBeginMaint:
            {
                var err = _w.BeginMaintenance(r.Token, "пользователь " + clientSid, clientElevated);
                return new IpcResponse { Ok = err == null, Error = err };
            }
            case Ipc.CmdHistory:
                return new IpcResponse { Ok = true, History = _w.History() };
            default:
                return IpcResponse.Fail("Неизвестная команда: " + r.Cmd);
        }
    }
}
