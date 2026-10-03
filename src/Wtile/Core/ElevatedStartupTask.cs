using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.UI.WindowsAndMessaging;

namespace Wtile.Core;

// A per-user Run key entry is always started with a standard token, so starting elevated at
// login needs a scheduled task instead. Mutually exclusive with StartupRegistration: both
// enabled would race two Wtiles at login, and only one survives the single-instance mutex.
internal static class ElevatedStartupTask
{
    private const string TaskName = "Wtile";
    private const int ErrorCancelled = 1223;
    private static bool _changing;

    public static bool IsEnabled()
    {
        if (Environment.ProcessPath is not string exePath)
            return false;
        (int exitCode, string output) = RunSchtasks($"/Query /TN \"{TaskName}\" /XML");
        return exitCode == 0
            && string.Equals(StartupTaskXml.ReadCommand(output), exePath, StringComparison.OrdinalIgnoreCase);
    }

    // Applies general.launchOnBoot and general.launchOnBootElevated together, so the Run key is
    // only touched once the task is known to be in the matching state.
    public static void ApplyConfig(bool? launchOnBootElevated, bool? launchOnBoot)
    {
        if (launchOnBootElevated == true)
        {
            if (IsEnabled())
                StartupRegistration.SetEnabled(false);
            else
                SetEnabled(true);
            return;
        }

        bool taskMustBeOff = launchOnBootElevated == false || launchOnBoot == true;
        if (taskMustBeOff && !SetEnabled(false))
            return;
        StartupRegistration.ApplyConfig(launchOnBoot);
    }

    public static bool SetEnabled(bool enabled)
    {
        if (_changing)
            return false;
        _changing = true;
        try
        {
            if (enabled)
                return Register();
            return !TaskExists() || RunSchtasksElevated($"/Delete /TN \"{TaskName}\" /F", "Removed elevated logon task.");
        }
        finally
        {
            _changing = false;
        }
    }

    private static bool Register()
    {
        if (Environment.ProcessPath is not string exePath)
        {
            Console.WriteLine("[launch-on-boot] Can't resolve this exe's path; elevated task not registered.");
            return false;
        }

        string xmlPath = Path.Combine(Path.GetTempPath(), $"wtile-task-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(xmlPath, StartupTaskXml.Build($"{Environment.UserDomainName}\\{Environment.UserName}", exePath), Encoding.Unicode);
            if (!RunSchtasksElevated($"/Create /TN \"{TaskName}\" /XML \"{xmlPath}\" /F", $"Registered elevated logon task for {exePath}"))
                return false;
            StartupRegistration.SetEnabled(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine($"[launch-on-boot] Failed to write the task definition: {ex.Message}");
            return false;
        }
        finally
        {
            try { File.Delete(xmlPath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private static bool TaskExists() => RunSchtasks($"/Query /TN \"{TaskName}\"").ExitCode == 0;

    private static (int ExitCode, string Output) RunSchtasks(string arguments)
    {
        try
        {
            using Process? process = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                StandardOutputEncoding = Encoding.UTF8,
            });
            if (process is null)
                return (-1, "");
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, output);
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return (-1, "");
        }
    }

    // Creating or deleting a highest-privilege task needs admin rights: a non-elevated Wtile asks
    // once through UAC instead of failing.
    private static bool RunSchtasksElevated(string arguments, string successMessage)
    {
        int exitCode = Environment.IsPrivilegedProcess ? RunSchtasks(arguments).ExitCode : RunSchtasksThroughUac(arguments);
        if (exitCode == 0)
            Console.WriteLine($"[launch-on-boot] {successMessage}");
        else if (exitCode != ErrorCancelled)
            Console.WriteLine($"[launch-on-boot] schtasks {arguments} failed (exit {exitCode}).");
        return exitCode == 0;
    }

    private static int RunSchtasksThroughUac(string arguments)
    {
        try
        {
            using Process? process = Process.Start(new ProcessStartInfo("schtasks.exe", arguments)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            });
            if (process is null)
                return -1;
            WaitWhilePumpingMessages(process);
            return process.ExitCode;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            Console.WriteLine("[launch-on-boot] Administrator permission was declined; nothing changed.");
            return ErrorCancelled;
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return -1;
        }
    }

    // The UAC prompt can stay open indefinitely, and this runs on the thread that owns the
    // keyboard hook and every window: blocking it would freeze Wtile and let Windows drop the hook.
    private static unsafe void WaitWhilePumpingMessages(Process process)
    {
        HANDLE handle = new(process.Handle);
        while (PInvoke.MsgWaitForMultipleObjects(1, &handle, false, PInvoke.INFINITE, QUEUE_STATUS_FLAGS.QS_ALLINPUT) == WAIT_EVENT.WAIT_OBJECT_0 + 1)
        {
            while (PInvoke.PeekMessage(out MSG msg, HWND.Null, 0, 0, PEEK_MESSAGE_REMOVE_TYPE.PM_REMOVE))
            {
                if (msg.message == PInvoke.WM_QUIT)
                {
                    PInvoke.PostQuitMessage((int)msg.wParam.Value);
                    return;
                }
                PInvoke.TranslateMessage(msg);
                PInvoke.DispatchMessage(msg);
            }
        }
    }
}
