use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{path::PathBuf, process::{Command, Output, Stdio}};
use tauri::Manager;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn engine_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let path = app
        .path()
        .resource_dir()
        .map_err(|e| format!("Application resources are unavailable: {e}"))?
        .join("binaries")
        .join("mailscope-engine.exe");
    if !path.is_file() {
        return Err(format!("Analysis engine was not found: {}", path.display()));
    }
    Ok(path)
}

fn run_engine(app: &tauri::AppHandle, args: &[&str]) -> Result<Output, String> {
    let program = engine_path(app)?;
    let data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Application data directory is unavailable: {e}"))?;
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("Application data directory could not be created: {e}"))?;

    let mut command = Command::new(program);
    command
        .args(args)
        .env("MAILSCOPE_DATA_DIR", data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);

    command.output().map_err(|e| format!("Analysis engine could not be started: {e}"))
}

fn parse_engine<T: DeserializeOwned>(output: Output) -> Result<T, String> {
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if error.is_empty() {
            format!("Analysis engine exited with code {:?}.", output.status.code())
        } else {
            error
        });
    }
    serde_json::from_slice::<T>(&output.stdout).map_err(|e| {
        let text = String::from_utf8_lossy(&output.stdout);
        format!("Analysis engine returned invalid data: {e}. Output: {text}")
    })
}

#[tauri::command]
fn engine_status(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["version"])? )
}

#[tauri::command]
fn ui_bootstrap(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["ui-bootstrap"])? )
}

#[tauri::command]
fn analyze_email(app: tauri::AppHandle, file_path: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["analyze", &file_path])?)
}

#[tauri::command]
fn list_history(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["history"])? )
}

#[tauri::command]
fn get_analysis(app: tauri::AppHandle, analysis_id: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["get", &analysis_id])?)
}

#[tauri::command]
fn refresh_intelligence(app: tauri::AppHandle, analysis_id: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["refresh-intelligence", &analysis_id])?)
}

#[tauri::command]
fn delete_analysis(app: tauri::AppHandle, analysis_id: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["delete", &analysis_id])?)
}

#[tauri::command]
fn dashboard_stats(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["stats"])?)
}

#[tauri::command]
fn list_iocs(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["iocs"])?)
}

#[tauri::command]
fn export_analysis(app: tauri::AppHandle, analysis_id: String, output_path: String, report_format: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["export", &analysis_id, &output_path, &report_format])?)
}

#[tauri::command]
fn get_settings(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["settings-get"])? )
}

#[tauri::command]
fn save_settings(app: tauri::AppHandle, settings: Value) -> Result<Value, String> {
    let text = serde_json::to_string(&settings).map_err(|e| format!("Settings could not be encoded: {e}"))?;
    parse_engine(run_engine(&app, &["settings-put", &text])?)
}

#[tauri::command]
fn get_case(app: tauri::AppHandle, analysis_id: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["case-get", &analysis_id])?)
}

#[tauri::command]
fn save_case(app: tauri::AppHandle, analysis_id: String, changes: Value) -> Result<Value, String> {
    let text = serde_json::to_string(&changes).map_err(|e| format!("Case update could not be encoded: {e}"))?;
    parse_engine(run_engine(&app, &["case-put", &analysis_id, &text])?)
}

#[tauri::command]
fn list_audit(app: tauri::AppHandle, limit: u32) -> Result<Value, String> {
    let limit_text = limit.clamp(1, 1000).to_string();
    parse_engine(run_engine(&app, &["audit", &limit_text])?)
}

#[tauri::command]
fn create_backup(app: tauri::AppHandle, output_path: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["backup-create", &output_path])?)
}

#[tauri::command]
fn restore_backup(app: tauri::AppHandle, input_path: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["backup-restore", &input_path])?)
}

#[tauri::command]
fn get_yara_status(app: tauri::AppHandle) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["yara-status"])?)
}

#[tauri::command]
fn import_yara_rule(app: tauri::AppHandle, path: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["yara-import", &path])?)
}

#[tauri::command]
fn set_yara_rule_active(app: tauri::AppHandle, name: String, digest: String) -> Result<Value, String> {
    parse_engine(run_engine(&app, &["yara-set-active", &name, &digest])?)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            engine_status,
            ui_bootstrap,
            analyze_email,
            list_history,
            get_analysis,
            refresh_intelligence,
            delete_analysis,
            dashboard_stats,
            list_iocs,
            export_analysis,
            get_settings,
            save_settings,
            get_case,
            save_case,
            list_audit,
            create_backup,
            restore_backup,
            get_yara_status,
            import_yara_rule,
            set_yara_rule_active
        ])
        .run(tauri::generate_context!())
        .expect("error while running MailScope");
}
