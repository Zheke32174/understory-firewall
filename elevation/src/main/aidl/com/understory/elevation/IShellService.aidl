// IShellService.aidl
//
// The contract for the Shizuku-hosted shell UserService. Shizuku starts
// ShellUserService in a process running at the shell uid (2000) that the user
// granted, and hands the app this binder. runCommand executes a command at
// that shell privilege and returns a flattened result.
package com.understory.elevation;

import com.understory.elevation.ShellResultParcel;

interface IShellService {
    // Run `cmd` (argv, already split — NOT a shell string) with an optional
    // millisecond timeout (0 = no timeout). Returns exit code + stdout + stderr.
    ShellResultParcel runCommand(in String[] cmd, long timeoutMs) = 1;

    // Ask the hosting process to stop itself (called from unbind paths).
    void destroy() = 2;
}
