using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SiteBlocker.Core;

namespace SiteBlocker.App;

/// <summary>Клиент канала службы. Одно соединение, переподключение при сбое, таймауты.</summary>
public sealed class PipeClient : IDisposable
{
    private readonly object _gate = new();
    private NamedPipeClientStream? _pipe;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    public string? LastError { get; private set; }

    public IpcResponse? Request(IpcRequest req, int timeoutMs = 4000)
    {
        lock (_gate)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                try
                {
                    if (_pipe == null || !_pipe.IsConnected)
                    {
                        Reset();
                        _pipe = Open(1500);
                        _reader = new StreamReader(_pipe, new UTF8Encoding(false));
                        _writer = new StreamWriter(_pipe, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
                    }
                    _writer!.WriteLine(Json.Serialize(req, false));
                    var t = _reader!.ReadLineAsync();
                    if (!t.Wait(timeoutMs)) throw new TimeoutException("Служба не ответила вовремя");
                    var line = t.Result ?? throw new IOException("Соединение закрыто");
                    LastError = null;
                    return Json.Deserialize<IpcResponse>(line);
                }
                catch (Exception e)
                {
                    LastError = e.Message;
                    Reset();
                }
            }
            return null;
        }
    }

    /// <summary>
    /// Подключение к каналу службы. Сначала стандартно (GENERIC_READ|GENERIC_WRITE). Если ACL не пускает
    /// (GENERIC_WRITE включает FILE_APPEND_DATA = FILE_CREATE_PIPE_INSTANCE, которого у обычных пользователей нет
    /// и быть не должно), — открываем с явными правами чтение + запись данных/атрибутов.
    /// </summary>
    private static NamedPipeClientStream Open(int timeoutMs)
    {
        // Identification: службе достаточно узнать, КТО клиент (SID, администратор ли), действовать от его имени она не может.
        var p = new NamedPipeClientStream(".", Ipc.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Identification);
        try { p.Connect(timeoutMs); return p; }
        catch (UnauthorizedAccessException)
        {
            p.Dispose();
            return OpenExplicit(timeoutMs);
        }
        catch { p.Dispose(); throw; }
    }

    private const uint GENERIC_READ = 0x80000000, FILE_WRITE_DATA = 0x2, FILE_WRITE_ATTRIBUTES = 0x100;
    private const uint OPEN_EXISTING = 3, FILE_FLAG_OVERLAPPED = 0x40000000, SECURITY_SQOS_PRESENT = 0x00100000, SECURITY_IDENTIFICATION = 0x00010000;
    private const int ERROR_PIPE_BUSY = 231;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafePipeHandle CreateFileW(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WaitNamedPipeW(string name, uint timeoutMs);

    private static NamedPipeClientStream OpenExplicit(int timeoutMs)
    {
        string path = @"\\.\pipe\" + Ipc.PipeName;
        var sw = Stopwatch.StartNew();
        while (true)
        {
            var h = CreateFileW(path, GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES, 0, IntPtr.Zero, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, IntPtr.Zero);
            if (!h.IsInvalid) return new NamedPipeClientStream(PipeDirection.InOut, true, true, h);
            int err = Marshal.GetLastWin32Error();
            h.Dispose();
            if (err == ERROR_PIPE_BUSY && sw.ElapsedMilliseconds < timeoutMs) { WaitNamedPipeW(path, 500); continue; }
            throw new Win32Exception(err, "Канал службы: " + new Win32Exception(err).Message);
        }
    }

    public Task<IpcResponse?> RequestAsync(IpcRequest req, int timeoutMs = 4000) => Task.Run(() => Request(req, timeoutMs));

    private void Reset()
    {
        try { _pipe?.Dispose(); } catch { }
        _pipe = null; _reader = null; _writer = null;
    }

    public void Dispose() { lock (_gate) Reset(); }
}
