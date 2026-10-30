// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a program's imports say it can do (commit 42g): the API calls
 * malware analysts group by capability. An import is a capability, not an
 * intent — a debugger imports what an injector does — so each group says
 * which calls it saw, and only the groups rarely seen in ordinary
 * programs are warnings. Windows names match with or without their A/W
 * (ANSI/wide) and Ex suffixes; POSIX names with or without Mach-O's
 * leading underscore.
 *
 * Pure: unit:preview-facts.
 */

export interface Capability {
	/** What the imports let it do, after "it can": "write into other processes". */
	what: string;
	/** Rare in ordinary programs: a warning. */
	strong: boolean;
	calls: string[];
}

const WINDOWS: [string, boolean, string[]][] = [
	["write into other processes (code injection)", true, ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "SetThreadContext", "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtWriteVirtualMemory", "NtMapViewOfSection"]],
	["watch the keyboard (a keylogger's calls)", true, ["SetWindowsHookEx", "GetAsyncKeyState", "RegisterRawInputDevices", "GetRawInputData"]],
	["download from the internet", true, ["URLDownloadToFile", "URLDownloadToCacheFile", "InternetOpenUrl", "InternetReadFile", "HttpSendRequest", "WinHttpSendRequest", "WinHttpReadData"]],
	["read saved passwords or credentials", true, ["CryptUnprotectData", "CredEnumerate", "CredRead", "LsaRetrievePrivateData", "MiniDumpWriteDump", "SamConnect", "VaultEnumerateItems"]],
	["install or start a service", true, ["CreateService", "StartService", "ChangeServiceConfig"]],
	["hide from debuggers", true, ["CheckRemoteDebuggerPresent", "NtSetInformationThread", "ZwSetInformationThread", "NtQueryInformationProcess"]],
	["raise its own privileges", true, ["AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "DuplicateTokenEx", "SetTokenInformation"]],
	["shut the computer down", false, ["ExitWindowsEx", "InitiateSystemShutdown", "NtShutdownSystem"]],
	["read other processes' memory, or list them", false, ["ReadProcessMemory", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "EnumProcesses"]],
	["encrypt data", false, ["CryptEncrypt", "CryptGenKey", "CryptImportKey", "BCryptEncrypt", "BCryptGenerateSymmetricKey"]],
	["use network sockets", false, ["WSAStartup", "socket", "connect", "bind", "listen", "send", "recv", "gethostbyname", "getaddrinfo", "WSASocket", "InternetOpen", "WinHttpOpen"]],
	["run other programs", false, ["CreateProcess", "WinExec", "ShellExecute", "CreateProcessAsUser", "CreateProcessWithToken"]],
	["change the registry", false, ["RegSetValue", "RegCreateKey", "RegDeleteValue", "RegDeleteKey"]],
	["read and write the clipboard", false, ["GetClipboardData", "SetClipboardData"]],
	["take screenshots", false, ["BitBlt", "GetDIBits"]],
	["find its functions at run time", false, ["LoadLibrary", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"]],
	["check for a debugger", false, ["IsDebuggerPresent", "OutputDebugString"]],
];

const POSIX: [string, boolean, string[]][] = [
	["trace or attach to processes (ptrace)", true, ["ptrace"]],
	["load kernel modules", true, ["init_module", "finit_module", "delete_module"]],
	["read the keychain or saved passwords", true, ["SecKeychainFindGenericPassword", "SecKeychainFindInternetPassword", "SecItemCopyMatching", "SecKeychainItemCopyContent"]],
	["watch the keyboard or the screen (macOS)", true, ["CGEventTapCreate", "IOHIDManagerOpen", "CGWindowListCreateImage", "CGDisplayCreateImage", "AXIsProcessTrusted"]],
	["run other programs", false, ["execve", "execl", "execlp", "execv", "execvp", "system", "popen", "posix_spawn", "posix_spawnp", "fork", "vfork"]],
	["use network sockets", false, ["socket", "connect", "bind", "listen", "accept", "getaddrinfo", "gethostbyname"]],
	["change who it runs as", false, ["setuid", "setgid", "seteuid", "setresuid"]],
	["detach into the background", false, ["daemon", "setsid"]],
	["load code at run time", false, ["dlopen", "dlsym"]],
	["make memory executable", false, ["mprotect"]],
	["encrypt data", false, ["EVP_EncryptInit_ex", "AES_set_encrypt_key", "CCCrypt", "SecKeyCreateEncryptedData"]],
];

const strip = (n: string) => n.replace(/@.*$/, "").replace(/^_+/, "");

export function capabilities(names: string[], windows: boolean): Capability[] {
	const have = new Map<string, string>();
	for (const n of names) {
		const s = strip(n);
		have.set(windows ? s.replace(/(?:Ex)?[AW]?$/, "").replace(/Ex$/, "") : s, n);
		have.set(s, n);
	}
	const table = windows ? WINDOWS : POSIX;
	const out: Capability[] = [];
	for (const [what, strong, calls] of table) {
		const seen = calls.filter((c) => have.has(c) || have.has(c.replace(/Ex$/, "")));
		if (seen.length) out.push({ what, strong, calls: seen });
	}
	// The reverse shell's shape: a socket, its descriptor duplicated onto
	// the standard streams, and a shell run on them.
	if (!windows) {
		const h = (c: string) => have.has(c);
		if (h("socket") && h("dup2") && (h("execve") || h("execl") || h("execlp") || h("system"))) out.unshift({ what: "make a reverse shell (a socket, dup2 onto the standard streams, a shell)", strong: true, calls: ["socket", "dup2", h("execve") ? "execve" : h("system") ? "system" : "execl"] });
	}
	return out;
}
