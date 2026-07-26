use crate::core::{CompoundParserInput, ParserFileProvider, ParserInput, ParserSource};
use anyhow::{Context, Result, anyhow, bail};
use libsqlite3_sys as ffi;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::ptr;
use tempfile::TempDir;

pub(crate) struct SqliteEvidence {
    _tempdir: TempDir,
    path: PathBuf,
    source_label: String,
    copied_sidecars: Vec<String>,
    source_files: Vec<SqliteSourceFile>,
}

#[derive(Debug, Clone)]
pub(crate) struct SqliteSourceFile {
    pub(crate) role: String,
    pub(crate) path: String,
    pub(crate) artifact_id: Option<i64>,
    pub(crate) system_file_id: Option<i64>,
    pub(crate) fs_identifier: Option<u64>,
}

impl SqliteEvidence {
    pub(crate) fn from_input(input: ParserInput, filename: &str) -> Result<Self> {
        let tempdir = tempfile::tempdir().context("failed to create temporary SQLite directory")?;
        let path = tempdir.path().join(filename);
        let mut source_label = "<in-memory>".to_string();
        let mut copied_sidecars = Vec::new();
        let mut source_files = Vec::new();

        match input {
            ParserInput::Path(source) => {
                fs::copy(&source, &path).with_context(|| {
                    format!("failed to copy SQLite database from {}", source.display())
                })?;
                source_label = source.display().to_string();
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });

                for suffix in ["-wal", "-shm"] {
                    let sidecar = append_suffix(&source, suffix)?;
                    if sidecar.exists() {
                        let target = append_suffix(&path, suffix)?;
                        fs::copy(&sidecar, &target).with_context(|| {
                            format!("failed to copy SQLite sidecar {}", sidecar.display())
                        })?;
                        copied_sidecars.push(suffix.trim_start_matches('-').to_string());
                        source_files.push(SqliteSourceFile {
                            role: sqlite_role_for_suffix(suffix).to_string(),
                            path: sidecar.display().to_string(),
                            artifact_id: None,
                            system_file_id: None,
                            fs_identifier: None,
                        });
                    }
                }
            }
            ParserInput::Bytes(bytes) => {
                fs::write(&path, bytes).context("failed to write SQLite bytes to temp file")?;
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });
            }
            ParserInput::ReadSeek(mut reader) => {
                let mut bytes = Vec::new();
                reader.seek(SeekFrom::Start(0))?;
                reader.read_to_end(&mut bytes)?;
                fs::write(&path, bytes).context("failed to write SQLite stream to temp file")?;
                source_files.push(SqliteSourceFile {
                    role: "primary".to_string(),
                    path: source_label.clone(),
                    artifact_id: None,
                    system_file_id: None,
                    fs_identifier: None,
                });
            }
            ParserInput::Compound(compound) => {
                source_label = compound.primary.original_path.clone();
                write_compound_sqlite(compound, &path, &mut copied_sidecars, &mut source_files)?;
            }
        }

        Ok(Self {
            _tempdir: tempdir,
            path,
            source_label,
            copied_sidecars,
            source_files,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn source_label(&self) -> String {
        self.source_label.clone()
    }

    pub(crate) fn copied_sidecars(&self) -> &[String] {
        &self.copied_sidecars
    }

    pub(crate) fn source_files(&self) -> &[SqliteSourceFile] {
        &self.source_files
    }
}

fn write_compound_sqlite(
    mut compound: CompoundParserInput,
    path: &Path,
    copied_sidecars: &mut Vec<String>,
    source_files: &mut Vec<SqliteSourceFile>,
) -> Result<()> {
    let primary = compound.primary.clone();
    copy_source_to_path(&mut *compound.provider, &primary, path)?;
    source_files.push(source_file_from_parser_source(&primary));

    for companion in compound.companions {
        let Some(suffix) = sqlite_suffix_for_role(&companion.role) else {
            continue;
        };
        let target = append_suffix(path, suffix)?;
        copy_source_to_path(&mut *compound.provider, &companion, &target)?;
        copied_sidecars.push(suffix.trim_start_matches('-').to_string());
        source_files.push(source_file_from_parser_source(&companion));
    }

    Ok(())
}

fn copy_source_to_path(
    provider: &mut dyn ParserFileProvider,
    source: &ParserSource,
    path: &Path,
) -> Result<()> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("failed to create SQLite temp file {}", path.display()))?;
    provider.copy_to(source, &mut file)?;
    Ok(())
}

fn source_file_from_parser_source(source: &ParserSource) -> SqliteSourceFile {
    SqliteSourceFile {
        role: source.role.clone(),
        path: source.original_path.clone(),
        artifact_id: source.artifact_id,
        system_file_id: source.system_file_id,
        fs_identifier: source.fs_identifier,
    }
}

fn sqlite_suffix_for_role(role: &str) -> Option<&'static str> {
    match role {
        "sqlite_wal" => Some("-wal"),
        "sqlite_shm" => Some("-shm"),
        _ => None,
    }
}

fn sqlite_role_for_suffix(suffix: &str) -> &'static str {
    match suffix {
        "-wal" => "sqlite_wal",
        "-shm" => "sqlite_shm",
        _ => "sqlite_companion",
    }
}

fn append_suffix(path: &Path, suffix: &str) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("SQLite path has no file name: {}", path.display()))?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(suffix);
    Ok(path.with_file_name(sidecar_name))
}

pub(crate) struct SqliteConnection {
    handle: *mut ffi::sqlite3,
}

impl SqliteConnection {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let conn =
            Self::open_with_flags(path, ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_NOMUTEX)?;
        conn.execute_batch("PRAGMA query_only = ON;")?;
        Ok(conn)
    }

    #[cfg(test)]
    pub(crate) fn create_for_test(path: &Path) -> Result<Self> {
        Self::open_with_flags(
            path,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_NOMUTEX,
        )
    }

    fn open_with_flags(path: &Path, flags: i32) -> Result<Self> {
        let path = path.to_string_lossy();
        let path = CString::new(path.as_bytes()).context("SQLite path contains NUL byte")?;
        let mut handle = ptr::null_mut();
        let rc = unsafe { ffi::sqlite3_open_v2(path.as_ptr(), &mut handle, flags, ptr::null()) };

        if rc != ffi::SQLITE_OK {
            let message = if handle.is_null() {
                "failed to allocate SQLite handle".to_string()
            } else {
                sqlite_error(handle)
            };
            if !handle.is_null() {
                unsafe {
                    ffi::sqlite3_close(handle);
                }
            }
            bail!("failed to open SQLite database: {message}");
        }

        Ok(Self { handle })
    }

    pub(crate) fn execute_batch(&self, sql: &str) -> Result<()> {
        let sql = CString::new(sql).context("SQLite SQL contains NUL byte")?;
        let mut errmsg = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.handle,
                sql.as_ptr(),
                None,
                ptr::null_mut(),
                &mut errmsg,
            )
        };

        if rc != ffi::SQLITE_OK {
            let message = if errmsg.is_null() {
                sqlite_error(self.handle)
            } else {
                let message = unsafe { CStr::from_ptr(errmsg).to_string_lossy().into_owned() };
                unsafe {
                    ffi::sqlite3_free(errmsg.cast());
                }
                message
            };
            bail!("SQLite execution failed: {message}");
        }

        Ok(())
    }

    pub(crate) fn query_rows(
        &self,
        sql: &str,
        mut row_fn: impl FnMut(&SqliteStatement<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut statement = SqliteStatement::prepare(self, sql)?;
        while statement.step()? {
            row_fn(&statement)?;
        }
        Ok(())
    }

    pub(crate) fn schema(&self) -> Result<SqliteSchema> {
        SqliteSchema::load(self)
    }
}

impl Drop for SqliteConnection {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_close(self.handle);
        }
    }
}

pub(crate) struct SqliteStatement<'conn> {
    conn: &'conn SqliteConnection,
    stmt: *mut ffi::sqlite3_stmt,
}

impl<'conn> SqliteStatement<'conn> {
    fn prepare(conn: &'conn SqliteConnection, sql: &str) -> Result<Self> {
        let sql = CString::new(sql).context("SQLite SQL contains NUL byte")?;
        let mut stmt = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(conn.handle, sql.as_ptr(), -1, &mut stmt, ptr::null_mut())
        };

        if rc != ffi::SQLITE_OK {
            bail!(
                "failed to prepare SQLite statement: {}",
                sqlite_error(conn.handle)
            );
        }

        Ok(Self { conn, stmt })
    }

    fn step(&mut self) -> Result<bool> {
        let rc = unsafe { ffi::sqlite3_step(self.stmt) };
        match rc {
            ffi::SQLITE_ROW => Ok(true),
            ffi::SQLITE_DONE => Ok(false),
            _ => bail!(
                "SQLite statement failed: {}",
                sqlite_error(self.conn.handle)
            ),
        }
    }

    pub(crate) fn i64(&self, index: i32) -> Option<i64> {
        if self.column_is_null(index) {
            None
        } else {
            Some(unsafe { ffi::sqlite3_column_int64(self.stmt, index) })
        }
    }

    pub(crate) fn f64(&self, index: i32) -> Option<f64> {
        if self.column_is_null(index) {
            None
        } else {
            Some(unsafe { ffi::sqlite3_column_double(self.stmt, index) })
        }
    }

    pub(crate) fn bool(&self, index: i32) -> Option<bool> {
        self.i64(index).map(|value| value != 0)
    }

    pub(crate) fn text(&self, index: i32) -> Option<String> {
        if self.column_is_null(index) {
            return None;
        }

        let ptr = unsafe { ffi::sqlite3_column_text(self.stmt, index) };
        if ptr.is_null() {
            return None;
        }

        let len = unsafe { ffi::sqlite3_column_bytes(self.stmt, index) };
        if len <= 0 {
            return Some(String::new());
        }

        let bytes = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    pub(crate) fn blob(&self, index: i32) -> Option<Vec<u8>> {
        if self.column_is_null(index) {
            return None;
        }

        let len = unsafe { ffi::sqlite3_column_bytes(self.stmt, index) };
        if len <= 0 {
            return Some(Vec::new());
        }

        let ptr = unsafe { ffi::sqlite3_column_blob(self.stmt, index) };
        if ptr.is_null() {
            return None;
        }

        let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), len as usize) };
        Some(bytes.to_vec())
    }

    fn column_is_null(&self, index: i32) -> bool {
        unsafe { ffi::sqlite3_column_type(self.stmt, index) == ffi::SQLITE_NULL }
    }
}

impl Drop for SqliteStatement<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_finalize(self.stmt);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SqliteSchema {
    tables: BTreeMap<String, BTreeSet<String>>,
}

impl SqliteSchema {
    fn load(conn: &SqliteConnection) -> Result<Self> {
        let mut table_names = Vec::new();
        conn.query_rows(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;",
            |row| {
                if let Some(name) = row.text(0) {
                    table_names.push(name);
                }
                Ok(())
            },
        )?;

        let mut tables = BTreeMap::new();
        for table in table_names {
            let mut columns = BTreeSet::new();
            let sql = format!("PRAGMA table_info({});", quote_identifier(&table));
            // Some Apple databases ship FTS/virtual tables backed by proprietary
            // modules or tokenizers (e.g. AddressBook's `ab_cf_tokenizer`) that
            // stock SQLite cannot load. `PRAGMA table_info` on such a table
            // errors; skip it rather than aborting the whole schema load, since
            // parsers only care about the plain data tables.
            let result = conn.query_rows(&sql, |row| {
                if let Some(name) = row.text(1) {
                    columns.insert(name);
                }
                Ok(())
            });
            if let Err(err) = result {
                log::debug!("skipping table {table} during schema load: {err}");
                continue;
            }
            tables.insert(table, columns);
        }

        Ok(Self { tables })
    }

    pub(crate) fn has_table(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    pub(crate) fn has_column(&self, table: &str, column: &str) -> bool {
        self.tables
            .get(table)
            .map(|columns| columns.contains(column))
            .unwrap_or(false)
    }

    pub(crate) fn missing_columns(&self, table: &str, columns: &[&str]) -> Vec<String> {
        columns
            .iter()
            .filter(|column| !self.has_column(table, column))
            .map(|column| format!("{table}.{column}"))
            .collect()
    }
}

pub(crate) fn select_column(
    schema: &SqliteSchema,
    table: &str,
    alias: &str,
    column: &str,
    output_alias: &str,
) -> String {
    if schema.has_column(table, column) {
        format!("{alias}.{column} AS {output_alias}")
    } else {
        format!("NULL AS {output_alias}")
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn sqlite_error(handle: *mut ffi::sqlite3) -> String {
    unsafe {
        CStr::from_ptr(ffi::sqlite3_errmsg(handle))
            .to_string_lossy()
            .into_owned()
    }
}
