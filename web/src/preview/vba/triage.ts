// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What a macro would do (commit 42h, docs/PREVIEWS.md › Macros): read,
 * never run — the questions olevba answers, asked of each module:
 *
 *   when      what runs by itself: on open (AutoOpen, Document_Open,
 *             Workbook_Open, Auto_Open…), on close, or by an ActiveX
 *             control's own event (InkPicture1_Painted, Frame1_Layout —
 *             an automatic start that is not called AutoOpen)
 *   what      running programs, making COM objects, downloading, writing
 *             files, reading the environment, calling Windows directly
 *             (Declare … Lib "kernel32": VirtualAlloc, RtlMoveMemory,
 *             CreateThread — a shellcode loader's three calls), Excel 4
 *             macros, rewriting VBA itself, keystrokes, sandbox checks,
 *             payloads read from the document's own text, cells, shapes,
 *             properties or forms
 *   how       obfuscation: characters built one at a time, reversed
 *             strings, long hex or base64 runs, lines thousands long
 *
 * Each finding names the module and the line; the 42f script triage
 * (text/script.ts) runs on the source too, for the command lines and
 * addresses inside the strings. Comments are skipped.
 * Pure: unit:preview-facts.
 */

import { scanScript, type ScriptReport } from "../text/script.ts";
import type { VbaModule } from "./project.ts";

export interface MacroFinding {
	module: string;
	line: number;
	what: string;
	excerpt: string;
}

export interface MacroTriage {
	/** What runs by itself, and when. */
	autorun: (MacroFinding & { when: "open" | "close" | "control" | "new" })[];
	findings: MacroFinding[];
	/** Windows functions it declares, and the library. */
	declares: { name: string; lib: string; module: string; line: number }[];
	obfuscation: string[];
	script: ScriptReport;
}

const AUTORUN: [RegExp, "open" | "close" | "control" | "new"][] = [
	[/^(?:AutoOpen|AutoExec|Auto_Open|Workbook_Open|Workbook_Activate|Document_Open|DocumentOpen|App_DocumentOpen|App_WorkbookOpen|Auto_Activate|Presentation_Open|Workbook_WindowActivate)$/i, "open"],
	[/^(?:AutoNew|Document_New|App_NewDocument)$/i, "new"],
	[/^(?:AutoClose|AutoExit|Auto_Close|Document_Close|Document_BeforeClose|DocumentBeforeClose|Workbook_BeforeClose|Workbook_Close|App_DocumentBeforeClose)$/i, "close"],
	// ActiveX controls' own events that fire as the document is drawn (the
	// list olevba keeps) — not Initialize or Click, which need the form
	// shown or a person's click.
	[/^\w+_(?:Painted|Painting|Layout|Resize|GotFocus|LostFocus|MouseHover|MouseMove|MouseEnter|MouseLeave|BeforeNavigate2|NavigateComplete2|DocumentComplete|DownloadBegin|DownloadComplete|ProgressChange|StatusTextChange|TitleChange|BeforeScriptExecute)$/i, "control"],
];

/** [what it does, the pattern] — the first match a line wins. */
const RULES: [string, RegExp][] = [
	["runs a program (Shell)", /\b(?:VBA\.)?Shell\s*\(|\bShell\s+["\w]/i],
	["runs a program (WScript.Shell / ShellExecute)", /WScript\.Shell|Shell\.Application|\bShellExecute\w*\b|\.ShellExecute\b|\bWinExec\b/i],
	["runs AppleScript or a Unix command (Mac)", /\bMacScript\b|\bAppleScriptTask\b|\bpopen\b|\bsystem\s*\(/i],
	["downloads from the internet", /\bURLDownloadToFile\w*|MSXML2\.(?:Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|\bNet\.WebClient\b|\bDownloadFile\b|\bDownloadString\b|InternetExplorer\.Application|\bInternetOpenUrl\w*/i],
	["writes a file and saves it", /ADODB\.Stream|\.SaveToFile\b|\.CreateTextFile\b|\bOpen\s+.+\s+For\s+(?:Output|Binary|Append)\b|\bPut\s+#|\bPrint\s+#|\bWrite\s+#/i],
	["copies, moves or deletes files", /\bFileCopy\b|\.CopyFile\b|\.MoveFile\b|\bKill\s+|\.DeleteFile\b|\bName\s+.+\s+As\s+/i],
	["makes a COM object", /\bCreateObject\s*\(|\bGetObject\s*\(/i],
	["runs Excel 4.0 macros", /\bExecuteExcel4Macro\b|\.Run\s*\(?\s*"(?:EXEC|CALL|REGISTER)\(/i],
	["calls a procedure by name (hides what it calls)", /\bCallByName\b|\bApplication\.Run\b|\bEvaluate\s*\(/i],
	["rewrites VBA code (writes macros into other files)", /\bVBProject\b|\.CodeModule\b|\bVBComponents\b|AccessVBOM/i],
	["reads the environment (user, temp folder, computer)", /\bEnviron\$?\s*\(/i],
	["changes the registry", /\.RegWrite\b|\.RegDelete\b|\bSaveSetting\b/i],
	["sends keystrokes to other windows", /\bSendKeys\b|\bAppActivate\b/i],
	["checks if it runs in a sandbox (recent files, user name, screen)", /RecentFiles\.Count|Application\.UserName|\.BuiltInDocumentProperties\s*\(\s*"Author"|Tasks\.Exists|GetSystemMetrics/i],
	["reads text hidden in the document (properties, shapes, cells, forms)", /BuiltInDocumentProperties|CustomDocumentProperties|\.Shapes\s*\(.+\.TextFrame|\.AlternativeText\b|ActiveDocument\.(?:Content|Range|Paragraphs)|\.Cells\s*\(.+\.Value\b|\.Controls\s*\(.+\.(?:Text|Value|Caption)|\bUserForm\d*\.\w+\.(?:Text|Value|Caption)/i],
	["hides what it does from the user", /\.Visible\s*=\s*False|DisplayAlerts\s*=\s*False|ScreenUpdating\s*=\s*False|\bvbHide\b/i],
	["mentions PowerShell or the command prompt", /\bpowershell\b|\bcmd(?:\.exe)?\s+\/[ck]\b|\bmshta\b|\bwscript\b|\bcscript\b|\brundll32\b|\bregsvr32\b|\bcertutil\b|\bbitsadmin\b|\bschtasks\b/i],
];

/** Windows functions a macro has no ordinary reason to call. */
const DANGEROUS_API = /^(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|RtlMoveMemory|RtlCopyMemory|CreateThread|CreateRemoteThread|WriteProcessMemory|NtWriteVirtualMemory|EnumSystemLanguageGroups[AW]?|EnumDateFormats\w*|CallWindowProc[AW]?|URLDownloadToFile[AW]?|ShellExecute[AW]?|WinExec|CreateProcess[AW]?|LoadLibrary[AW]?|GetProcAddress|HeapCreate|HeapAlloc|SetWindowsHookEx[AW]?|GetAsyncKeyState)$/i;

const isComment = (l: string) => /^\s*(?:'|Rem\b)/i.test(l);

export function triage(modules: VbaModule[]): MacroTriage {
	const autorun: MacroTriage["autorun"] = [];
	const findings: MacroFinding[] = [];
	const declares: MacroTriage["declares"] = [];
	const seen = new Set<string>();
	let chr = 0;
	let reversed = 0;
	let concat = 0;
	let longLine = 0;
	let hexRuns = 0;
	let b64Runs = 0;
	for (const m of modules) {
		const lines = m.source.split("\n");
		lines.forEach((raw, i) => {
			const line = raw.trim();
			if (!line || isComment(line) || /^Attribute VB_/i.test(line)) return;
			const sub = /^(?:(?:Public|Private|Friend)\s+)?(?:Static\s+)?(?:Sub|Function)\s+([A-Za-z_]\w*)/i.exec(line);
			if (sub) {
				const hit = AUTORUN.find(([re]) => re.test(sub[1]!));
				if (hit) autorun.push({ module: m.name, line: i + 1, what: sub[1]!, excerpt: line.slice(0, 160), when: hit[1] });
			}
			const decl = /^(?:(?:Public|Private)\s+)?Declare\s+(?:PtrSafe\s+)?(?:Sub|Function)\s+(\w+)\s+Lib\s+"([^"]+)"(?:\s+Alias\s+"([^"]+)")?/i.exec(line);
			if (decl) declares.push({ name: decl[3] ?? decl[1]!, lib: decl[2]!, module: m.name, line: i + 1 });
			for (const [what, re] of RULES) {
				if (seen.has(what) || !re.test(line)) continue;
				seen.add(what);
				findings.push({ module: m.name, line: i + 1, what, excerpt: line.slice(0, 160) });
				break;
			}
			chr += (line.match(/\bChr[BW]?\$?\s*\(/gi) ?? []).length;
			reversed += (line.match(/\bStrReverse\s*\(/gi) ?? []).length;
			concat += (line.match(/"\s*&\s*"/g) ?? []).length;
			if (raw.length > 1500) longLine++;
			hexRuns += (line.match(/"[0-9A-Fa-f]{60,}"/g) ?? []).length;
			b64Runs += (line.match(/"[A-Za-z0-9+/]{60,}={0,2}"/g) ?? []).length;
		});
	}
	const obfuscation: string[] = [];
	if (chr > 20) obfuscation.push(`${chr} characters built one at a time with Chr()`);
	if (reversed) obfuscation.push(`${reversed} strings reversed with StrReverse()`);
	if (concat > 40) obfuscation.push(`strings cut into ${concat} pieces and joined`);
	if (hexRuns) obfuscation.push(`${hexRuns} long hex strings (an encoded payload, likely)`);
	if (b64Runs) obfuscation.push(`${b64Runs} long base64 strings (an encoded payload, likely)`);
	if (longLine) obfuscation.push(`${longLine} lines over 1,500 characters long`);
	// The 42f triage, on everything the project holds as text: the source,
	// what its compiled code says that the source does not, its forms.
	const all = [...modules.map((m) => m.source.replace(/""/g, '"')), ...modules.flatMap((m) => m.unseen), ...modules.flatMap((m) => m.formText)].join("\n");
	return { autorun, findings, declares, obfuscation, script: scanScript(all) };
}

export const dangerousApi = (name: string) => DANGEROUS_API.test(name);
