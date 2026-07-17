# Windows Section UIAccess UAC Bypass

## Summary

This tool exploits a flaw in Windows where mapped images can differ from their disk content to elevate local privileges (very similar to Process Herpaderping, minus the "manually spawning a process" part). It does this by mapping an injector image into memory, replacing it on disk with a valid Microsoft binary, and then executing it. The image has the `UIAccess` flag, meaning we are able to inject into high privilege processes running under our own user account.

For `UIAccess` to work, we need to place our injector in a trusted directory which has not been blacklisted. At the time of writing we can use the `Logs/WMI` directory in `System32`, as it is world-writable and not blacklisted by UAC. An alternative directory could be the `Steam` directory in `Program Files (x86)`, if Steam is installed on the machine.

The injector itself is not very special, it's basically just a simple `SetWindowsHookEx` DLL injector.

**This bypasses UAC even if it's set to "Always Notify"**

## The exploit in more detail

Whenever Windows deals with images (the executable kind), it usually relies on the kernel to relocate and map these images into a process, whether you'd be dealing with processes or modules. The underlying mechanism for this is `NtCreateSection` with the `SEC_IMAGE` flag. This instructs the Windows kernel to map a provided file handle into memory and perform the necessary relocations on it (and probably more, I haven't checked).

The flaw lies in the fact that at any point in time another process tries to map the same file into memory, Windows detects that the file is already mapped into memory, and instead of mapping the file again, will just hand out a copy of the existing section (probably done for optimization reasons). We can abuse this by using a file handle with write permissions to alter the file on disk after mapping it into memory. As long as the section handle is never closed, executing the file either by running it as a process, or loading it as a module, will cause it to load the previously mapped section instead of the contents on disk.

This mismatch can be abused to trick UAC or other authoritative applications that use the disk contents for validation into thinking they are dealing with a completely different image then what is actually being executed. In the case of UAC, this can be abused to spoof the signer of the application, whilst [still inhereting the manifest of the mapped application](https://x.com/daxcess/status/2070410481676825002). However this does not only alter the way UAC _displays_ its popup, this can also be used to perform auto-elevation or UIAccess elevation: a complete UAC bypass.

Of course for this to work we need to be able to write into a world-writable directory that UAC deems secure. Unfortunately for auto-elevation I was not able to find such a directory, however UIAccess elevation seems to be less strict, and a candidate directory was quickly discovered: `System32\Logs\WMI` (requires being a member of `BUILTIN\Performance Log Users`). Alternatively as described before, if the machine just so happens to have Steam installed, that can also be used as it resides in `Program Files`. There are probably more applications that this will work on, but I have not checked any further.

Now that we have `UIAccess`, we can rather simply escalate privileges using a good 'ol `SetWindowsHookEx` DLL injection. Of course, this assumes that there is currently an administrative application with windows open in the current session. We can force this to happen by using the Windows Task Scheduler to our advantage. Windows ships with many built-in tasks that are set to run with the highest privileges available. Most of these tasks exit very quickly though, and that would make this exploit unreliable. To overcome this, we make use of a global `SetWindowsHookEx` hook, targeting all running applications _before_ we even spawn the privileged process, and making sure our payload only executes in the correct circumstances. Now that the hook is in place, we can ask the Task Scheduler to spawn `taskhostw.exe` with Administrator privileges, which due to the `SetWindowsHookEx` hook almost immediately spawns an elevated command prompt. In the case that `taskhostw.exe` was already running, we use `PostThreadMessageA` to force it to run our `WH_GETMESSAGE` callback, loading our module, and spawning the command prompt.
