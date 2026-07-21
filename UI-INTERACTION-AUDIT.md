# MailScope UI Interaction Audit

Audit target: MailScope 1.0.11

This document maps every interactive area in the current desktop UI to its actual behavior and records interaction gaps discovered in the React, Tauri and Python engine paths.

## Removed display-only areas

- The top-right `Engine ready · IPC ...` status pill was removed.
- The bottom-left `Privacy-first / Local IPC analysis` card was removed.
- Engine availability is still checked in the background and continues to control whether `Start Analysis` can be used.

## Global navigation

| Interactive area | Result |
|---|---|
| Dashboard | Replaces the main content with local totals and recent analyses. |
| New Analysis | Opens the email selection screen or preserves the current analysis result if one is already loaded. |
| History | Loads the saved-analysis table from the local engine database. |
| IOC Explorer | Loads saved cases, automatically selects the first case and opens its IOC workspace. |
| Threat Intelligence | Loads locally saved online-intelligence settings and provider status cards. |
| Reports | Loads saved analyses into the export form. |
| Settings | Loads locally saved query settings and API-key fields. |

Navigation changes only the page state. It does not clear an existing global error banner.

## New Analysis — file selection state

| Interactive area | Result |
|---|---|
| Large file-selection area | Opens the native Windows file picker filtered to `.eml`. |
| Select `.eml` file | The click bubbles to the surrounding selection area and opens the same native picker. |
| File-picker cancel | Makes no changes. |
| Successful file selection | Displays the full path, clears a previously loaded analysis and enables `Start Analysis` if the engine is available. |
| Start Analysis | Sends the path to the Tauri `analyze_email` command. The label changes to `Analyzing…` and the button becomes disabled while running. |
| Successful analysis | Saves the result locally, refreshes dependent counters, opens the result view and selects `Overview`. |
| Failed analysis | Restores the button and shows the engine error in the global error banner. |

`Start Analysis` is disabled when no file is selected, the engine did not pass its startup check, or analysis is already running.

The selection area supports the native Tauri file-drop event as well as mouse and keyboard activation. Non-`.eml` drops produce a visible error.

## New Analysis — result state

| Tab/button | Result |
|---|---|
| Overview | Shows subject, sender, Reply-To, Return-Path, date, Message-ID, source size and SHA-256. |
| Findings | Shows heuristic findings, evidence, severity and source tool. |
| Tools | Shows the risk banner and individual local/online tool reports, metrics and details. |
| IOCs | Shows extracted indicator type, value, scope and source. |
| Attachments | Shows attachment type, size, entropy, flags and hashes. |
| Headers | Shows raw email headers in a text block. |
| Raw | Shows the extracted plain-text preview, falling back to the HTML preview. |
| Analyze another email | Clears the current result and selected path, returning to file selection. The saved result remains in History. |

Overview values, IOC values, attachment hashes, raw headers and raw content now have explicit copy actions. Summary, finding and tool cards remain intentionally display-only.

## Dashboard

| Interactive area | Result |
|---|---|
| Recent-analysis subject/file button | Loads that analysis, switches to `New Analysis` and displays its result. |

Analysis totals, Unique IOCs, Attachments and With errors are display-only summary cards. Clicking the rest of a history row does nothing; only the subject/file button opens it. Dashboard has no manual refresh or delete control.

## History

| Interactive area | Result |
|---|---|
| Search history | Filters immediately by file name, subject, sender address or SHA-256. No engine request is made per keystroke. |
| Refresh | Requests the saved-analysis list again. |
| Subject/file button | Loads the analysis and switches to its result under `New Analysis`. |
| Trash icon | Opens the native confirmation prompt `Delete this saved analysis?`. |
| Confirm deletion | Permanently deletes the analysis and its stored workspace, reloads History and refreshes shared counters. |
| Cancel deletion | Makes no changes. |

Delete failures are caught and shown in the global error banner. Successful deletion removes both the database row and the extracted attachment workspace.

## IOC Explorer

| Interactive area | Result |
|---|---|
| Saved-case button | Clears the previous case, shows loading state and requests the selected analysis. |
| ALL | Shows every valid IOC from the selected analysis. |
| URL / DOMAIN / IPV4 / IPV6 / EMAIL | Filters the table to that exact IOC type. |
| Search in selected analysis | Applies a case-insensitive filter to normalized IOC values. |
| Hide duplicates | When enabled, keeps the first matching type/value pair. |

Selecting the page automatically selects the first saved analysis. Loading failures replace the workspace with an error panel. Every IOC row now has an explicit copy action; reputation queries and details remain part of the analysis workflow rather than row clicks.

## Threat Intelligence

| Interactive area | Result |
|---|---|
| Use online providers checkbox | Changes only the component's unsaved state. It takes effect after `Save provider settings`. |
| Save provider settings | Writes the settings to the local engine settings file and shows a success message. |

Provider cards are not buttons. They do not open provider sites, API-key fields or result details.

Provider labels now state `NO KEY NEEDED`, `KEY SAVED`, `KEY REQUIRED` or `DISABLED`. The page explicitly explains that these are configuration states and that live availability is verified during analysis.

Leaving the page before saving discards checkbox changes. Save failures are caught and shown in the global error banner.

## Reports

| Interactive area | Result |
|---|---|
| Saved analysis selector | Chooses one locally saved analysis. The first result is selected automatically. |
| Format selector | Chooses HTML report, JSON evidence or CSV indicators. |
| Export report | Opens the native save dialog with the matching extension. |
| Save-dialog cancel | Makes no changes. |
| Confirm save | Calls `export_analysis`; success displays the saved path and failure uses the global error banner. |

The export button is disabled when there is no saved analysis. Initial list failures and save/export failures are caught and shown in the global error banner.

## Settings

| Interactive area | Result |
|---|---|
| History retention selector | Selects unlimited, 30-day or 90-day retention. Saving immediately prunes expired database rows and their extracted workspaces; later engine operations enforce it again. |
| Enable online intelligence | Controls the master online-intelligence setting after saving. |
| Query Hashes / URLs / Domains / IP addresses | Changes the intended query policy after saving. Actual engine enforcement has gaps listed below. |
| Maximum lookups per provider | Stores a numeric limit; the engine clamps its use to 1–25. |
| VirusTotal / OTX / AbuseIPDB API key fields | Store masked text locally after saving. |
| Disabled upload checkboxes | Cannot be clicked. The engine also forcibly saves both upload settings as `false`. |
| Save settings | Writes retention to browser local storage, saves engine settings and displays a success message. |

Leaving the page before saving discards changes. Save errors are caught and shown in the global error banner.

## Native window controls

The Windows title-bar minimize, maximize/restore and close buttons are provided by the operating system/Tauri window. They are independent of React page actions.

## Functional verification

The packaged engine was exercised in an isolated temporary data directory with online intelligence disabled:

- settings save: passed
- sample `.eml` analysis: passed
- History listing: passed
- open saved analysis: passed
- Dashboard stats: passed
- IOC listing: passed
- HTML export: passed
- JSON export: passed
- CSV export: passed
- delete analysis: passed
- History empty after delete: passed

## Resolved findings in 1.0.11

- URL, domain, IP and hash permissions are filtered before provider candidate lists are built, so a disabled type cannot reach ThreatFox, VirusTotal, OTX or any other provider.
- The unused `auto_check_online` setting was removed from the normalized settings schema.
- History retention is enforced by the engine and removes expired database rows plus extracted attachment workspaces.
- Manual deletion also removes the analysis workspace.
- Provider labels describe configuration state rather than claiming live health.
- An unavailable engine presents a visible retry control without restoring the removed IPC pill.
- Dashboard, History, Reports, Threat Intelligence, Settings, file-dialog and export failures now produce visible errors.
- Navigation clears stale global errors.
- Native `.eml` drag-and-drop and keyboard activation are supported.
- Copy actions were added to analysis details, IOC values, attachment hashes, raw headers and raw content.
