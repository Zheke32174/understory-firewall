// Minimal AIDL surface for the optional Shizuku-hosted diagnostic helper.
//
// This binder runs inside a process with whatever privilege the user's Shizuku
// setup grants (adb shell, or root) — but the ONLY thing it can do is execute a
// small fixed allowlist of READ-ONLY diagnostic commands (see
// ShizukuUserService.ALLOWLIST). There is no free-form command execution and no
// write/flash/AT-command path of any kind.
package com.ant.emichaosbg;

interface IShizukuDiagService {
    // Runs one allowlisted read-only diagnostic by key and returns its captured
    // stdout (or an "error: ..." string on failure). See ShizukuUserService.
    String runDiagnostic(String key);

    // Lets the caller confirm the remote process is alive and query its uid,
    // so the UI can show "connected as root" vs "connected as shell".
    int remoteUid();

    void destroy();
}
