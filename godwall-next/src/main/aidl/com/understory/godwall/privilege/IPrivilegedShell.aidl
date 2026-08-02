// IPrivilegedShell.aidl
//
// The contract Godwall needs from Yojimbo, and the ONLY privileged contract in
// this module. Yojimbo hosts a process at a privileged uid and hands Godwall
// this binder through YojimboPrivilegeProvider.call("attach", …).
//
// argv is already split — it is exec(), not a shell string, so nothing in
// Godwall can be turned into a command-injection surface by a package name.
package com.understory.godwall.privilege;

import com.understory.godwall.privilege.ShellOutcome;

interface IPrivilegedShell {
    // Run argv with an optional millisecond timeout (0 = no timeout).
    ShellOutcome exec(in String[] argv, long timeoutMs) = 1;

    // Ask the hosting process to release this shell.
    void release() = 2;
}
