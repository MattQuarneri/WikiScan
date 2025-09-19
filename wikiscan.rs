// Developed by Matthew Quarneri 2025 (matt@mentic.com)

use anyhow::{bail, Context, Result};
use bzip2::read::{BzDecoder, MultiBzDecoder};
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::env;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Reusable container for Terminal/TCP REPL modes
mod appserv;
use crate::appserv::{start_tcp_server as start_tcp_server_generic, start_terminal, ReplService};

#[derive(Clone)]
struct WikiScanService;

impl ReplService for WikiScanService {
    fn run_session<R, W>(&self, stdin: R, out: W, enable_colors: bool) -> anyhow::Result<()>
    where
        R: BufRead + Send + 'static,
        W: Write + Send + 'static,
    {
        // Delegate to existing REPL implementation
        run_repl(stdin, out, enable_colors)
    }
}

const SETTINGS_FILE: &str = "settings.ini";

// ANSI colors
const C_RESET: &str = "\x1b[0m";
const C_GRAY: &str = "\x1b[90m";  // bright black
const C_BLUE: &str = "\x1b[34m";
const C_WHITE: &str = "\x1b[97m";

/// Lightweight console progress ticker with spinner and percentage.
struct ProgressTicker {
    label: String,
    total: u64,
    spin: usize,
    last: Instant,
}

// Settings file utilities
fn read_settings_file() -> Result<(Option<String>, Option<String>)> {
    let path = Path::new(SETTINGS_FILE);
    if !path.exists() { return Ok((None, None)); }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", SETTINGS_FILE))?;
    let mut last_w: Option<String> = None;
    let mut last_i: Option<String> = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("W=") {
            last_w = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("I=") {
            last_i = Some(v.trim().to_string());
        }
    }
    Ok((last_w, last_i))
}

fn write_settings_file(w: Option<&str>, i: Option<&str>) -> Result<()> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(wp) = w { lines.push(format!("W={}", wp)); }
    if let Some(ik) = i { lines.push(format!("I={}", ik)); }
    let data = lines.join("\n");
    std::fs::write(SETTINGS_FILE, data)
        .with_context(|| format!("writing {}", SETTINGS_FILE))?;
    Ok(())
}

/// Very rough plaintext renderer: strips common wiki markup and HTML-ish tags.
/// This is intentionally simple and fast; it won't handle all nested constructs.
fn render_plaintext(src: &str) -> String {
    let mut s = src.to_string();

    // Remove HTML comments
    if let Ok(re) = Regex::new(r"(?s)<!--.*?-->") { s = re.replace_all(&s, "").into_owned(); }
    // Remove <ref>...</ref> and self-closing variants
    if let Ok(re) = Regex::new(r"(?si)<ref\b[^>]*?>.*?</ref>") { s = re.replace_all(&s, "").into_owned(); }
    if let Ok(re) = Regex::new(r"(?si)<ref\b[^>]*/>") { s = re.replace_all(&s, "").into_owned(); }
    // Remove other HTML tags but keep inner text
    if let Ok(re) = Regex::new(r"(?si)</?[^>]+>") { s = re.replace_all(&s, "").into_owned(); }

    // Headings lines like == Heading ==
    if let Ok(re) = Regex::new(r"(?m)^={2,6}\s*(.*?)\s*={2,6}\s*$") { s = re.replace_all(&s, "$1\n").into_owned(); }

    // Templates {{...}} — naive non-nested removal; iterate a few times
    if let Ok(re) = Regex::new(r"(?s)\{\{[^{}]*\}\}") {
        for _ in 0..5 { let new_s = re.replace_all(&s, "").into_owned(); if new_s.len() == s.len() { break; } s = new_s; }
    }

    // Bold/italic markup
    s = s.replace("'''", "");
    s = s.replace("''", "");

    // Internal links [[Target|Text]] -> Text, [[Target]] -> Target
    if let Ok(re) = Regex::new(r"\[\[([^\]|\n]+)\|([^\]]+)\]\]") { s = re.replace_all(&s, "$2").into_owned(); }
    if let Ok(re) = Regex::new(r"\[\[([^\]]+)\]\]") { s = re.replace_all(&s, "$1").into_owned(); }

    // External links [http://... Text] -> Text, or drop URL if no text
    if let Ok(re) = Regex::new(r"\[(?:https?://[^\s\]]+)\s+([^\]]+)\]") { s = re.replace_all(&s, "$1").into_owned(); }
    if let Ok(re) = Regex::new(r"\[(?:https?://[^\s\]]+)\]") { s = re.replace_all(&s, "").into_owned(); }

    // Unescape some HTML entities (very limited)
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&nbsp;", " ");

    // Collapse excessive whitespace
    if let Ok(re) = Regex::new(r"[ \t\x0B\f\r]+") { s = re.replace_all(&s, " ").into_owned(); }
    if let Ok(re) = Regex::new(r"\n{3,}") { s = re.replace_all(&s, "\n\n").into_owned(); }

    s.trim().to_string()
}

impl ProgressTicker {
    fn new(label: &str, total: u64) -> Self {
        Self { label: label.to_string(), total, spin: 0, last: Instant::now() }
    }
    fn tick(&mut self, current: u64, extra: &str) {
        if self.last.elapsed() < Duration::from_millis(500) { return; }
        let spinner = ["-", "\\", "|", "/"]; // note: escaped backslash
        let s = spinner[self.spin % spinner.len()];
        self.spin = self.spin.wrapping_add(1);
        let pct = if self.total > 0 { (current as f64) * 100.0 / (self.total as f64) } else { 0.0 };
        eprint!("{} {}: {:.2}% {}\r", s, self.label, pct, extra);
        let _ = std::io::Write::flush(&mut std::io::stderr());
        self.last = Instant::now();
    }
    fn finish(&self) {
        eprintln!("");
    }
}

struct Page {
    title: String,
    ns: u32,
    page_id: u64,
    revision_id: u64,
    timestamp: String,
    contributor: Option<String>,
    comment: Option<String>,
    text: String,  // raw wikitext
}

#[derive(Serialize, Clone)]
pub struct Article {
    pub title: String,
    pub page_id: u64,
    pub wikitext: String,
    pub headings: Vec<Heading>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Heading {
    pub level: u8,         // 1..=6
    pub text: String,
    pub byte_start: usize, // offsets within wikitext
    pub byte_end: usize,
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub offset: u64,     // byte offset into the compressed multistream .bz2
    pub page_id: u64,
    pub title: String,
}

struct NamedIndex {
    name: String,
    map: HashMap<String, u64>,
}

struct Session {
    dump_path: Option<String>,
    // Stack of indexes: first is master, last is current
    indexes: Vec<NamedIndex>,
}

impl Session {
    fn new() -> Self { Self { dump_path: None, indexes: Vec::new() } }
    fn has_index(&self) -> bool { !self.indexes.is_empty() }
    fn current_index_len(&self) -> usize { self.indexes.last().map(|n| n.map.len()).unwrap_or(0) }
}

/// Simple Read adapter that counts bytes read from the inner reader.
struct CountingRead<R: Read> {
    inner: R,
    bytes: u64,
}

impl<R: Read> CountingRead<R> {
    fn new(inner: R) -> Self { Self { inner, bytes: 0 } }
    fn bytes_read(&self) -> u64 { self.bytes }
}

impl<R: Read> Read for CountingRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }
}

/// Atomic variant that allows progress reporting from other contexts.
struct CountingReadAtomic<R: Read> {
    inner: R,
    bytes: Arc<AtomicU64>,
}

impl<R: Read> CountingReadAtomic<R> {
    fn new(inner: R, bytes: Arc<AtomicU64>) -> Self { Self { inner, bytes } }
}

impl<R: Read> Read for CountingReadAtomic<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Quickly validate that the dump path points to a readable bz2 file by attempting to decompress a small chunk.
fn validate_dump_readable(dump_bz2_path: &str) -> Result<usize> {
    let file = File::open(dump_bz2_path)
        .with_context(|| format!("opening dump: {}", dump_bz2_path))?;
    // Use MultiBzDecoder to ensure we can read concatenated members.
    let mut dec = MultiBzDecoder::new(BufReader::new(file));
    let mut buf = [0u8; 4096];
    let n = dec.read(&mut buf)
        .with_context(|| format!("decompressing from: {}", dump_bz2_path))?;
    if n == 0 { bail!("decompression returned 0 bytes"); }
    Ok(n)
}

/// Heuristic: scan the compressed dump file for bzip2 member headers ("BZh")
/// to infer candidate member start offsets when a multistream index is absent.
fn find_bzip2_member_offsets(dump_bz2_path: &str, cancel: Option<&Arc<AtomicBool>>) -> Result<Vec<u64>> {
    let mut f = File::open(dump_bz2_path)
        .with_context(|| format!("opening dump for header scan: {}", dump_bz2_path))?;
    let total_bytes = f.metadata()?.len();
    let mut buf = vec![0u8; 1024 * 1024]; // 1 MiB chunks
    let mut offsets = Vec::new();
    let mut file_pos: u64 = 0;
    let mut carry: Vec<u8> = Vec::new();
    let spinner = ["-","\\","|","/"];
    let mut spin_i = 0usize;
    let mut last_tick = Instant::now();
    loop {
        if let Some(flag) = cancel { if flag.load(Ordering::Relaxed) { break; } }
        let n = f.read(&mut buf)?;
        if n == 0 { break; }
        let slice = if carry.is_empty() { &buf[..n] } else {
            // prepend carry to handle boundary matches
            let mut tmp = Vec::with_capacity(carry.len() + n);
            tmp.extend_from_slice(&carry);
            tmp.extend_from_slice(&buf[..n]);
            carry.clear();
            let base_pos = file_pos.saturating_sub(tmp.len() as u64 - n as u64);
            for i in 0..tmp.len().saturating_sub(3) {
                // Stricter check: BZh followed by compression level '1'..='9'
                if tmp[i] == b'B' && tmp[i+1] == b'Z' && tmp[i+2] == b'h' {
                    let lvl = tmp[i+3];
                    if (b'1'..=b'9').contains(&lvl) {
                        offsets.push(base_pos + i as u64);
                    }
                }
            }
            if tmp.len() >= 3 { carry = tmp[tmp.len()-3..].to_vec(); } else { carry.clear(); }
            file_pos += n as u64;
            if last_tick.elapsed() >= Duration::from_secs(2) {
                let s = spinner[spin_i % spinner.len()];
                spin_i = spin_i.wrapping_add(1);
                let pct = if total_bytes > 0 { (file_pos as f64) * 100.0 / (total_bytes as f64) } else { 0.0 };
                eprint!("{} header-scan: {:.2}% of file (found {} members)\r", s, pct, offsets.len());
                let _ = std::io::Write::flush(&mut std::io::stderr());
                last_tick = Instant::now();
            }
            continue;
        };
        for i in 0..slice.len().saturating_sub(3) {
            if slice[i] == b'B' && slice[i+1] == b'Z' && slice[i+2] == b'h' {
                let lvl = slice[i+3];
                if (b'1'..=b'9').contains(&lvl) {
                    offsets.push(file_pos + i as u64);
                }
            }
        }
        if slice.len() >= 3 { carry = slice[slice.len()-3..].to_vec(); } else { carry.clear(); }
        file_pos += n as u64;
        if last_tick.elapsed() >= Duration::from_secs(2) {
            let s = spinner[spin_i % spinner.len()];
            spin_i = spin_i.wrapping_add(1);
            let pct = if total_bytes > 0 { (file_pos as f64) * 100.0 / (total_bytes as f64) } else { 0.0 };
            eprint!("{} header-scan: {:.2}% of file (found {} members)\r", s, pct, offsets.len());
            let _ = std::io::Write::flush(&mut std::io::stderr());
            last_tick = Instant::now();
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    // Validate candidates by attempting a tiny decompression at each offset.
    // This filters out false positives where "BZh" occurs in compressed data.
    // We also show progress, since this phase can be long on very large dumps.
    let mut valid = Vec::with_capacity(offsets.len());
    let mut vfile = File::open(dump_bz2_path)
        .with_context(|| format!("opening dump for header validation: {}", dump_bz2_path))?;
    let mut last_tick_v = Instant::now();
    let mut v_spin_i = 0usize;
    for (i, &off) in offsets.iter().enumerate() {
        if let Some(flag) = cancel { if flag.load(Ordering::Relaxed) { break; } }
        vfile.seek(SeekFrom::Start(off))?;
        // Limit validation read to avoid excessive I/O if offset is bogus.
        // Using a 64 KiB cap is typically enough for bzip2 to emit a byte if the header is valid.
        let limited = (&vfile).take(64 * 1024);
        let mut test = BzDecoder::new(BufReader::new(limited));
        let mut probe = [0u8; 1];
        match test.read(&mut probe) {
            Ok(0) => { /* invalid; skip */ }
            Ok(_) => valid.push(off),
            Err(_) => { /* invalid; skip */ }
        }
        if last_tick_v.elapsed() >= Duration::from_millis(500) {
            let s = spinner[v_spin_i % spinner.len()];
            v_spin_i = v_spin_i.wrapping_add(1);
            let pct = if !offsets.is_empty() { (i as f64 + 1.0) * 100.0 / (offsets.len() as f64) } else { 100.0 };
            eprint!("{} validating headers: {:.2}% (valid: {})\r", s, pct, valid.len());
            let _ = std::io::Write::flush(&mut std::io::stderr());
            last_tick_v = Instant::now();
        }
    }
    eprintln!("");
    Ok(valid)
}

/// Build a keyword index in-memory (Title -> member offset) using the multistream index.
fn build_keyword_index_mem(
    dump_bz2_path: &str,
    multistream_index_bz2: &str,
    keyword: &str,
) -> Result<(HashMap<String, u64>, u64, u64)> {
    // Prefer the multistream index; if missing, fall back to an existing {keyword}.idx in the dump directory
    let index: HashMap<String, IndexEntry> = if Path::new(multistream_index_bz2).exists() {
        load_index(multistream_index_bz2).context("loading multistream index")?
    } else {
        let dump_dir = Path::new(dump_bz2_path).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| Path::new(".").to_path_buf());
        let fallback_idx = dump_dir.join(format!("{}.idx", keyword));
        if fallback_idx.exists() {
            // Load keyword idx and synthesize IndexEntry values (page_id unknown -> 0)
            let km = load_keyword_idx(fallback_idx.to_string_lossy().as_ref())
                .with_context(|| format!("loading fallback keyword idx: {}", fallback_idx.display()))?;
            let mut out = HashMap::new();
            for (title, off) in km {
                out.entry(title.clone()).or_insert(IndexEntry { offset: off, page_id: 0, title });
            }
            out
        } else {
            bail!(
                "neither multistream index '{}' nor fallback '{}' found",
                multistream_index_bz2,
                fallback_idx.display()
            );
        }
    };
    let mut offsets: Vec<u64> = {
        let mut s: HashSet<u64> = HashSet::new();
        for v in index.values() { s.insert(v.offset); }
        let mut v: Vec<u64> = s.into_iter().collect();
        v.sort_unstable();
        v
    };
    let kw_lower = keyword.to_lowercase();

    // Progress ticker
    let mut map: HashMap<String, u64> = HashMap::new();
    let mut pages_scanned: u64 = 0;
    let mut matches: u64 = 0;
    let total_members = offsets.len() as u64;
    let mut processed: u64 = 0;
    let mut ticker = ProgressTicker::new(&format!("scan members (mem idx '{}')", keyword), total_members);
    for off in offsets.drain(..) {
        visit_pages_in_member(dump_bz2_path, off, |title, text, _pid| {
            pages_scanned += 1;
            if !kw_lower.is_empty() && text.to_lowercase().contains(&kw_lower) {
                if !map.contains_key(title) {
                    map.insert(title.to_string(), off);
                }
                matches += 1;
            }
        }, None)?;
        processed += 1;
        ticker.tick(processed, &format!("members:{} matches:{} pages:{}", processed, matches, pages_scanned));
    }
    ticker.finish();
    Ok((map, pages_scanned, matches))
}

/// Filter a prior in-memory index by a keyword by rescanning only the relevant members.
fn filter_index_with_keyword(
    dump_bz2_path: &str,
    prior: &HashMap<String, u64>,
    keyword: &str,
) -> Result<(HashMap<String, u64>, u64, u64)> {
    let kw_lower = keyword.to_lowercase();
    let mut out: HashMap<String, u64> = HashMap::new();
    // Unique member offsets to visit
    let mut offsets: Vec<u64> = {
        let mut s = HashSet::new();
        for off in prior.values() { s.insert(*off); }
        let mut v: Vec<u64> = s.into_iter().collect();
        v.sort_unstable();
        v
    };
    let mut pages_scanned: u64 = 0;
    let mut matches: u64 = 0;
    let total_members = offsets.len() as u64;
    let mut processed: u64 = 0;
    let mut ticker = ProgressTicker::new(&format!("filter '{}'", keyword), total_members);
    for off in offsets.drain(..) {
        visit_pages_in_member(dump_bz2_path, off, |title, text, _pid| {
            // Only consider pages that were in the prior index
            if prior.contains_key(title) {
                pages_scanned += 1;
                if text.to_lowercase().contains(&kw_lower) {
                    if !out.contains_key(title) { out.insert(title.to_string(), off); }
                    matches += 1;
                }
            }
        }, None)?;
        processed += 1;
        ticker.tick(processed, &format!("members:{} matched:{} pages:{}", processed, matches, pages_scanned));
    }
    ticker.finish();
    Ok((out, pages_scanned, matches))
}

fn infer_multistream_index_path(dump_path: &str) -> Option<String> {
    // Replace trailing "multistream.xml.bz2" with "multistream-index.txt.bz2"
    let needle = "multistream.xml.bz2";
    if let Some(pos) = dump_path.rfind(needle) {
        let prefix = &dump_path[..pos];
        return Some(format!("{}multistream-index.txt.bz2", prefix));
    }
    None
}

fn start_interactive() -> Result<()> {
    // Use the generic terminal runner with our service
    let svc = WikiScanService;
    start_terminal(&svc)
}

fn run_repl<R: BufRead, W: Write>(mut stdin: R, mut out: W, enable_colors: bool) -> Result<()> {
    // Local color aliases (disabled in network contexts)
    let gray = if enable_colors { C_GRAY } else { "" };
    let blue = if enable_colors { C_BLUE } else { "" };
    let white = if enable_colors { C_WHITE } else { "" };
    let reset = if enable_colors { C_RESET } else { "" };

    writeln!(out, "🌐 WikiScan 🔍")?;
    // Color legend: name= is blue, <value> is white, rest is light gray
    writeln!(
        out,
        "{gray}{blue}W={reset}{white}{{filepath}}{reset}{gray} : sets the file path to wikipedia bz2 file{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(
        out,
        "{gray}{blue}I={reset}{white}{{<keyword>}}{reset}{gray}: build a RESUMABLE index saved to {{keyword}}.idx by scanning members and appending matches; resumes on rerun{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(
        out,
        "{gray}   During Indexing ({blue}I={reset}{gray}) you can press 'Q' then Enter to checkpoint and return to the menu{reset}",
        gray=gray, blue=blue, reset=reset
    )?;
    writeln!(
        out,
        "{gray}{blue}filter={reset}{white}{{<substring>}}{reset}{gray}: title-only filter of the current index (no dump scan); pushes a new index on the stack. Reducing index size improves search speed.{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(
        out,
        "{gray}{blue}search={reset}{white}{{<keyword>}}{reset}{gray}: Uses current index to look into the dump file for your target work; pushes a new index on the stack{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(out, "{gray}{blue}save={reset}{white}{{<save_name>}}{reset}{gray}: saves the current index to a file (title\\tcompressed byte offset per line){reset}", gray=gray, blue=blue, reset=reset, white=white)?;
    writeln!(
        out,
        "{gray}{blue}Page={reset}{white}{{<Page Title>}}{reset}{gray}: show the raw wikitext of the named page from the current index{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(
        out,
        "{gray}{blue}PageText={reset}{white}{{<Page Title>}}{reset}{gray}: show a rough plaintext rendering of the page (markup stripped){reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(
        out,
        "{gray}{blue}PageJSON={reset}{white}{{<Page Title>}}{reset}{gray}: print a JSON object with title, page_id, headings, and wikitext{reset}",
        gray=gray, blue=blue, reset=reset, white=white
    )?;
    writeln!(out, "{gray}show: list the first 100 titles in the current index{reset}", gray=gray, reset=reset)?;
    writeln!(out, "{gray}back: pop to the prior index and shows the count of items in the index{reset}", gray=gray, reset=reset)?;
    writeln!(out, "{gray}quit: exit the program{reset}", gray=gray, reset=reset)?;

    let mut session = Session::new();

    // Restore last session from settings.ini if available
    let (last_dump, last_idx_keyword) = read_settings_file()?;
    if let Some(p) = &last_dump {
        if Path::new(p.as_str()).exists() {
            session.dump_path = Some(p.clone());
            writeln!(out, "restored dump from settings: {}", p)?;
        }
    }
    if let Some(k) = &last_idx_keyword {
        let idx_path = format!("{}.idx", k);
        if Path::new(&idx_path).exists() {
            match load_keyword_idx(&idx_path) {
                Ok(map) => {
                    session.indexes.clear();
                    session.indexes.push(NamedIndex { name: k.to_string(), map });
                    writeln!(out, "restored index from settings: {} ({} entries)", idx_path, session.current_index_len())?;
                }
                Err(e) => eprintln!("warning: could not load index from settings ({}): {}", idx_path, e),
            }
        }
    }
    // Report startup status
    match &session.dump_path {
        Some(p) => writeln!(out, "Startup: W={} (dump path set)", p)?,
        None => writeln!(out, "Startup: W not set")?,
    }
    if let Some(cur) = session.indexes.last() {
        writeln!(out, "Startup: I={} ({} entries)", cur.name, cur.map.len())?;
    } else {
        writeln!(out, "Startup: I not set")?;
    }
    let mut warned_unset = false;
    loop {
        // Prompt with index depth and current size
        let (depth, size) = if session.indexes.is_empty() { (0usize, 0usize) } else { (session.indexes.len(), session.current_index_len()) };
        if !warned_unset && (session.dump_path.is_none() || !session.has_index()) {
            if session.dump_path.is_none() { writeln!(out, "Hint: set dump with W=/path/to/enwiki-*-multistream.xml.bz2")?; }
            if !session.has_index() { writeln!(out, "Hint: load/build an index with I=<keyword> or S=<keyword>")?; }
            warned_unset = true;
        }
        if session.dump_path.is_some() && session.has_index() {
           write!(out, "[i {} ({})] > ", depth, size)?;
        } else if session.dump_path.is_some() {
            write!(out, "I > ")?;
        } else {
            write!(out, "W > ")?;
        }
        out.flush()?;
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 { break; }
        let line = line.trim();
        if line.is_empty() { continue; }
        if line == "quit" || line == "exit" { break; }

        if let Some(p) = line.strip_prefix("W=") {
            if Path::new(p).exists() {
                session.dump_path = Some(p.to_string());
                writeln!(out, "set dump: {}", p)?;
                // Update settings.ini with last W and preserve last I
                let (_prev_w, prev_i) = read_settings_file()?;
                write_settings_file(Some(p), prev_i.as_deref())?;
                match validate_dump_readable(p) {
                    Ok(n) => {
                        writeln!(out, "ok: bz2 readable (read {} bytes)", n)?;
                        if let Some(ms_idx) = infer_multistream_index_path(p) {
                            if !Path::new(&ms_idx).exists() {
                                writeln!(out, "note: multistream index not found at '{}'\n      build or download '-multistream-index.txt.bz2' to enable i={{keyword}} search features", ms_idx)?;
                            }
                        }
                    }
                    Err(e) => {
                        writeln!(out, "warning: unable to read bz2: {}", e)?;
                    }
                }
            } else {
                writeln!(out, "file not found: {}", p)?;
            }
            continue;
        }

        // New: show page TEXT (plain) using the current index's member offset
        if let Some(title_in) = line.strip_prefix("PageText=").or_else(|| line.strip_prefix("pagetext=")) {
            let want_title = title_in.trim();
            if want_title.is_empty() { println!("provide a page title: PageText=<Title>"); continue; }
            let Some(dump) = session.dump_path.as_deref() else { println!("set dump path first: W={{path}}"); continue; };
            if !session.has_index() { println!("no index loaded. Use I={{keyword}} or S={{keyword}} first."); continue; }
            let cur = &session.indexes.last().unwrap().map;
            let mut found: Option<(&str, u64)> = cur.get_key_value(want_title).map(|(k, v)| (k.as_str(), *v));
            if found.is_none() { let norm = normalize_title(want_title); if let Some((k, v)) = cur.get_key_value(&norm) { found = Some((k.as_str(), *v)); } }
            if found.is_none() {
                let wlc = normalize_title(want_title).to_lowercase();
                for (k, v) in cur.iter() { if normalize_title(k).to_lowercase() == wlc { found = Some((k.as_str(), *v)); break; } }
            }
            let Some((resolved_title, off)) = found else { println!("title not in current index: {}", want_title); continue; };
            match extract_article(dump, off, resolved_title, 0) {
                Ok(article) => {
                    let plain = render_plaintext(&article.wikitext);
                    println!("===== {} (page_id: {}) =====", article.title, article.page_id);
                    println!("{}", plain);
                    println!("===== END {} =====", article.title);
                }
                Err(e) => println!("error extracting page '{}': {}", resolved_title, e),
            }
            continue;
        }

        // New: show page as JSON using the current index's member offset
        if let Some(title_in) = line.strip_prefix("PageJSON=").or_else(|| line.strip_prefix("pagejson=")) {
            let want_title = title_in.trim();
            if want_title.is_empty() { println!("provide a page title: PageJSON=<Title>"); continue; }
            let Some(dump) = session.dump_path.as_deref() else { println!("set dump path first: W={{path}}"); continue; };
            if !session.has_index() { println!("no index loaded. Use I={{keyword}} or S={{keyword}} first."); continue; }
            let cur = &session.indexes.last().unwrap().map;
            let mut found: Option<(&str, u64)> = cur.get_key_value(want_title).map(|(k, v)| (k.as_str(), *v));
            if found.is_none() { let norm = normalize_title(want_title); if let Some((k, v)) = cur.get_key_value(&norm) { found = Some((k.as_str(), *v)); } }
            if found.is_none() {
                let wlc = normalize_title(want_title).to_lowercase();
                for (k, v) in cur.iter() { if normalize_title(k).to_lowercase() == wlc { found = Some((k.as_str(), *v)); break; } }
            }
            let Some((resolved_title, off)) = found else { println!("title not in current index: {}", want_title); continue; };
            match extract_article(dump, off, resolved_title, 0) {
                Ok(article) => {
                    match serde_json::to_string_pretty(&article) {
                        Ok(js) => println!("{}", js),
                        Err(e) => println!("error serializing JSON: {}", e),
                    }
                }
                Err(e) => println!("error extracting page '{}': {}", resolved_title, e),
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("I=") {
            let Some(dump) = session.dump_path.as_deref() else {
                println!("set dump path first: W={{path}}");
                continue;
            };
            let keyword = rest.trim();
            if keyword.is_empty() { println!("provide a keyword: S={keyword}"); continue; }
            // Update settings.ini early with new I= keyword
            let (prev_w, _prev_i) = read_settings_file()?;
            write_settings_file(prev_w.as_deref(), Some(keyword))?;
            let Some(ms_index) = infer_multistream_index_path(dump) else {
                println!("could not infer multistream index path from dump: {}", dump);
                println!("expected file alongside dump ending with '-multistream-index.txt.bz2'");
                continue;
            };
            println!("Building/resuming on-disk index '{}'...", format!("{}.idx", keyword));
            println!("Press 'Q' then Enter at any time to stop and save a checkpoint.");
            use std::sync::Arc;
            use std::sync::atomic::{AtomicBool, Ordering};
            let cancel = Arc::new(AtomicBool::new(false));
            // Spawn a tiny watcher to read lines and set cancel on 'Q'/'q'.
            // Use /dev/tty on Unix to bypass IDE stdin buffering; fallback to stdin.
            let cancel_reader = {
                let cancel = Arc::clone(&cancel);
                std::thread::spawn(move || {
                    #[cfg(unix)]
                    let mut reader: Box<dyn std::io::BufRead + Send> = match std::fs::File::open("/dev/tty") {
                        Ok(f) => Box::new(std::io::BufReader::new(f)),
                        Err(_) => Box::new(std::io::BufReader::new(std::io::stdin())),
                    };
                    #[cfg(not(unix))]
                    let mut reader: Box<dyn std::io::BufRead + Send> = Box::new(std::io::BufReader::new(std::io::stdin()));

                    let mut buf = String::new();
                    while !cancel.load(Ordering::Relaxed) {
                        buf.clear();
                        use std::io::BufRead;
                        if reader.read_line(&mut buf).unwrap_or(0) == 0 { break; }
                        let s = buf.trim();
                        if s.eq_ignore_ascii_case("q") { cancel.store(true, Ordering::Relaxed); break; }
                    }
                })
            };
            let (_pages, matches, out_file) = build_keyword_index(dump, &ms_index, keyword, None, false, Some(&cancel))?;
            // Ensure the reader thread exits
            cancel.store(true, Ordering::Relaxed);
            let _ = cancel_reader.join();
            println!("Index updated: {} (matches so far: {})", out_file, matches);
            // Load the idx as the master index for subsequent search= filters
            match load_keyword_idx(&out_file) {
                Ok(map) => {
                    session.indexes.clear();
                    session.indexes.push(NamedIndex { name: keyword.to_string(), map });
                    println!("Master index loaded: {} ({} entries)", out_file, session.current_index_len());
                }
                Err(e) => {
                    println!("warning: failed to load idx into session: {}", e);
                }
            }
            continue;
        }

        if let Some(rest) = line.strip_prefix("S=") {
            let Some(dump) = session.dump_path.as_deref() else {
                println!("set dump path first: W={{path}}");
                continue;
            };
            let keyword = rest.trim();
            if keyword.is_empty() { println!("provide a keyword: i={keyword}"); continue; }
            let Some(ms_index) = infer_multistream_index_path(dump) else {
                println!("could not infer multistream index path from dump: {}", dump);
                println!("expected file alongside dump ending with '-multistream-index.txt.bz2'");
                continue;
            };
            println!("Building in-memory index for '{}'...", keyword);
            let (map, pages, matches) = build_keyword_index_mem(dump, &ms_index, keyword)?;
            session.indexes.clear();
            session.indexes.push(NamedIndex { name: keyword.to_string(), map });
            println!("Scanned pages: {}\nMatches: {}\nIndexed titles: {}", pages, matches, session.current_index_len());
            continue;
        }

        if let Some(rest) = line.strip_prefix("search=") {
            let Some(dump) = session.dump_path.as_deref() else {
                println!("set dump path first: W={{path}}");
                continue;
            };
            let keyword = rest.trim();
            if keyword.is_empty() { println!("provide a keyword: search={keyword}"); continue; }
            if !session.has_index() {
                println!("no prior index. Run i={{keyword}} first to build a base index.");
                continue;
            }
            let prior = &session.indexes.last().unwrap().map;
            println!("Filtering current index by '{}'...", keyword);
            let (map, _pages, matches) = filter_index_with_keyword(dump, prior, keyword)?;
            session.indexes.push(NamedIndex { name: keyword.to_string(), map });
            println!("New index size: {} (matched pages: {})", session.current_index_len(), matches);
            continue;
        }

        // New: title-only filter that does NOT scan the dump; filters the current index map
        if let Some(rest) = line.strip_prefix("filter=") {
            if !session.has_index() {
                println!("no prior index. Run i={{keyword}} first to build a base index.");
                continue;
            }
            let needle = rest.trim().to_lowercase();
            if needle.is_empty() { println!("provide a substring: filter={{substring}}"); continue; }
            let prior = &session.indexes.last().unwrap().map;
            let mut out: HashMap<String, u64> = HashMap::new();
            for (title, off) in prior.iter() {
                if title.to_lowercase().contains(&needle) {
                    out.insert(title.clone(), *off);
                }
            }
            session.indexes.push(NamedIndex { name: format!("title: {}", rest.trim()), map: out });
            println!("Title-filter applied. New index size: {}", session.current_index_len());
            continue;
        }

        // New: show page wikitext using the current index's member offset
        if let Some(title_in) = line.strip_prefix("Page=").or_else(|| line.strip_prefix("page=")) {
            let want_title = title_in.trim();
            if want_title.is_empty() {
                println!("provide a page title: Page=<Title>");
                continue;
            }
            let Some(dump) = session.dump_path.as_deref() else {
                println!("set dump path first: W={{path}}");
                continue;
            };
            if !session.has_index() {
                println!("no index loaded. Use I={{keyword}} or S={{keyword}} first.");
                continue;
            }
            // Resolve title to offset from current index
            let cur = &session.indexes.last().unwrap().map;
            // 1) exact match
            let mut found: Option<(&str, u64)> = cur.get_key_value(want_title).map(|(k, v)| (k.as_str(), *v));
            // 2) normalized match (space/underscore)
            if found.is_none() {
                let norm = normalize_title(want_title);
                if let Some((k, v)) = cur.get_key_value(&norm) { found = Some((k.as_str(), *v)); }
            }
            // 3) case-insensitive scan (fallback)
            if found.is_none() {
                let wlc = normalize_title(want_title).to_lowercase();
                for (k, v) in cur.iter() {
                    if normalize_title(k).to_lowercase() == wlc {
                        found = Some((k.as_str(), *v));
                        break;
                    }
                }
            }
            let Some((resolved_title, off)) = found else {
                println!("title not in current index: {}", want_title);
                continue;
            };
            match extract_article(dump, off, resolved_title, 0) {
                Ok(article) => {
                    println!("===== {} (page_id: {}) =====", article.title, article.page_id);
                    println!("{}", article.wikitext);
                    println!("===== END {} =====", article.title);
                }
                Err(e) => {
                    println!("error extracting page '{}': {}", resolved_title, e);
                }
            }
            continue;
        }

        if line == "back" {
            if session.indexes.len() > 1 {
                session.indexes.pop();
                println!("Index size: {}", session.current_index_len());
            } else if session.indexes.len() == 1 {
                // Keep at least master
                println!("At master index. Size: {}", session.current_index_len());
            } else {
                println!("No index loaded. Use i={{keyword}} first.");
            }
            continue;
        }

        if line == "show" {
            if !session.has_index() { println!("No index loaded."); continue; }
            let cur = &session.indexes.last().unwrap().map;
            for (i, title) in cur.keys().take(100).enumerate() {
                println!("{:>3}. {}", i + 1, title);
            }
            println!("Total: {}", cur.len());
            continue;
        }

        if line == "save" {
            if !session.has_index() { println!("No index loaded."); continue; }
            println!("Enter save path (or leave blank for default):");
            use std::io::Write;
            print!("> "); let _ = io::stdout().flush();
            let mut path = String::new();
            if io::stdin().read_line(&mut path)? == 0 { continue; }
            let path = path.trim();
            let cur = session.indexes.last().unwrap();
            let default_name = format!("{}.{}.idx", cur.name, cur.map.len());
            let out_path = if path.is_empty() { &default_name } else { path };
            let mut f = OpenOptions::new().create(true).truncate(true).write(true)
                .open(out_path).with_context(|| format!("opening {}", out_path))?;
            use std::io::Write as _;
            writeln!(f, "Title\tOffset")?;
            for (title, off) in &cur.map {
                writeln!(f, "{}\t{}", title, off)?;
            }
            println!("Saved {} entries to {}", cur.map.len(), out_path);
            continue;
        }

        println!("unknown command. Examples:\n  W=/path/to/enwiki-*-multistream.xml.bz2\n  I=keyword\n  S=keyword\n  search=pages have this word\n  filter=next index has this word\n show=show 100 page titles\n back=go back to prior index\n  Page=Title\n  PageText=Title\n  PageJSON=Title\n quit=exit the program\n");
    }

    Ok(())
}

/// Visit all pages inside a single bzip2 member starting at `offset`.
/// Calls `handler(title, text, page_id)` for each page.
/// If `cancel` is set, returns early when cancellation is requested.
fn visit_pages_in_member<F>(
    dump_bz2_path: &str,
    offset: u64,
    mut handler: F,
    cancel: Option<&Arc<AtomicBool>>,
) -> Result<()>
where
    F: FnMut(&str, &str, u64),
{
    let mut file = File::open(dump_bz2_path)?;
    file.seek(SeekFrom::Start(offset))?;
    let dec = BzDecoder::new(BufReader::new(file));
    let mut reader = Reader::from_reader(BufReader::new(dec));
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut in_page = false;
    let mut in_title = false;
    let mut in_id = false;
    let mut in_text = false;
    let mut cur_title = String::new();
    let mut cur_id: u64 = 0;
    let mut text = String::new();
    

    loop {
        if let Some(flag) = cancel { if flag.load(Ordering::Relaxed) { break; } }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"page" => { in_page = true; in_id = false; cur_title.clear(); text.clear(); cur_id = 0; }
                b"title" if in_page => in_title = true,
                b"id" if in_page && cur_id == 0 => in_id = true,
                b"text" if in_page => in_text = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"page" => {
                    handler(&cur_title, &text, cur_id);
                    in_page = false;
                }
                b"title" => in_title = false,
                b"id" => in_id = false,
                b"text" => in_text = false,
                _ => {}
            },
            Ok(Event::Text(e)) => {
                if in_title { cur_title.push_str(&e.unescape().unwrap_or_default()); }
                else if in_id {
                    if let Ok(v) = e.unescape().unwrap_or_default().parse::<u64>() { cur_id = v; }
                } else if in_text { text.push_str(&e.unescape().unwrap_or_default()); }
            }
            Ok(Event::Eof) => break, // end of this member
            Err(e) => bail!("XML error while scanning member @ {offset}: {e}"),
            _ => {}
        }
        buf.clear();
    }

    Ok(())
}

/// Build a keyword index file mapping Title -> multistream block offset.
/// Only valid for multistream dumps where `offset` points to a bzip2 member start.
pub fn build_keyword_index(
    dump_bz2_path: &str,
    multistream_index_bz2: &str,
    keyword: &str,
    out_path: Option<&str>,
    print_matches: bool,
    cancel: Option<&Arc<AtomicBool>>,
) -> Result<(u64, u64, String)> {
    // Prefer the multistream index; if missing, fall back to an existing {keyword}.idx in the dump directory
    let (mut offsets, total_members): (Vec<u64>, u64) = if Path::new(multistream_index_bz2).exists() {
        let index = load_index(multistream_index_bz2).context("loading multistream index")?;
        let mut offs: Vec<u64> = {
            let mut s: HashSet<u64> = HashSet::new();
            for v in index.values() { s.insert(v.offset); }
            let mut v: Vec<u64> = s.into_iter().collect();
            v.sort_unstable();
            v
        };
        let total = offs.len() as u64;
        (offs, total)
    } else {
        // Fallback 1: prior keyword idx
        let dump_dir = Path::new(dump_bz2_path).parent().map(|p| p.to_path_buf()).unwrap_or_else(|| Path::new(".").to_path_buf());
        let fallback_idx = dump_dir.join(format!("{}.idx", keyword));
        if fallback_idx.exists() {
            let km = load_keyword_idx(fallback_idx.to_string_lossy().as_ref())
                .with_context(|| format!("loading fallback keyword idx: {}", fallback_idx.display()))?;
            let mut s: HashSet<u64> = HashSet::new();
            for (_title, off) in km { s.insert(off); }
            let mut offs: Vec<u64> = s.into_iter().collect();
            offs.sort_unstable();
            let total = offs.len() as u64;
            (offs, total)
        } else {
            // Fallback 2: scan dump for bzip2 member headers so we can start building
            println!("note: multistream index not found; scanning dump for bzip2 member headers to begin indexing...");
            let mut offs = find_bzip2_member_offsets(dump_bz2_path, cancel)?;
            let total = offs.len() as u64;
            if total == 0 { bail!("no bzip2 members detected in dump: {}", dump_bz2_path); }
            (offs, total)
        }
    };
    // Determine output path: default to dump's parent directory
    let out_file = out_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let dump_dir = Path::new(dump_bz2_path)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| Path::new(".").to_path_buf());
            dump_dir.join(format!("{}.idx", keyword)).to_string_lossy().to_string()
        });

    // Ensure the idx file exists; if not, create an empty one so resumes have a place to write
    if !Path::new(&out_file).exists() {
        let empty: HashMap<String, u64> = HashMap::new();
        let _ = save_keyword_idx(&empty, &out_file);
    }

    // Load existing entries into an in-memory map to avoid duplicates and support periodic checkpoint saves
    let mut idx_map: HashMap<String, u64> = match load_keyword_idx(&out_file) {
        Ok(m) => m,
        Err(_) => HashMap::new(),
    };
    let mut existing: HashSet<String> = idx_map.keys().cloned().collect();
    let mut existing_max_off: u64 = idx_map.values().copied().max().unwrap_or(0);

    let kw_lower = keyword.to_lowercase();
    let mut pages_scanned: u64 = 0;
    let mut matches: u64 = 0;

    // Progress + resume setup
    let total_members = total_members;
    // Skip previously processed members by max offset seen in existing file.
    let mut processed_members: u64 = 0;
    if existing_max_off > 0 {
        let mut skipped = 0u64;
        offsets.retain(|off| {
            let keep = *off > existing_max_off;
            if !keep { skipped += 1; }
            keep
        });
        processed_members = skipped;
    }
    let mut last_sync = Instant::now();
    let mut ticker = ProgressTicker::new(&format!("build '{}'", keyword), total_members);

    let mut canceled = false;
    for off in offsets.drain(..) {
        if let Some(flag) = cancel { if flag.load(Ordering::Relaxed) { canceled = true; break; } }
        // Visit member; skip bad ones gracefully (e.g., bogus offsets)
        if let Err(e) = visit_pages_in_member(dump_bz2_path, off, |title, text, _pid| {
            pages_scanned += 1;
            if !kw_lower.is_empty() && text.to_lowercase().contains(&kw_lower) {
                if existing.insert(title.to_string()) {
                    // Update in-memory map; persistence handled by periodic save
                    idx_map.insert(title.to_string(), off);
                }
                matches += 1;
                if print_matches { println!("match: {} @ {}", title, off); }
            }
        }, cancel) {
            eprintln!("warning: skipping member @ {} due to error: {}", off, e);
        }
        processed_members += 1;

        // Periodic progress + checkpoint
        ticker.tick(processed_members, &format!("members:{} matches:{} pages:{}", processed_members, matches, pages_scanned));
        // Persist checkpoint to disk to survive crashes or restarts
        let _ = save_keyword_idx(&idx_map, &out_file);
        // Periodic durable sync
        if last_sync.elapsed() >= Duration::from_secs(15) {
            let _ = save_keyword_idx(&idx_map, &out_file);
            last_sync = Instant::now();
        }
        if let Some(flag) = cancel { if flag.load(Ordering::Relaxed) { canceled = true; break; } }
    }

    // Final save to ensure checkpoint
    let _ = save_keyword_idx(&idx_map, &out_file);

    // Ensure any carriage-return line is cleared
    ticker.finish();
    if canceled {
        println!("\nStopped. Checkpoint saved. Processed members: {}/{} | Matches: {} | Pages scanned: {}",
            processed_members, total_members, matches, pages_scanned);
    } else {
        println!("\nDone. Processed members: {}/{} | Matches: {} | Pages scanned: {}",
            processed_members, total_members, matches, pages_scanned);
    }
    Ok((pages_scanned, matches, out_file))
}

pub fn load_index(index_bz2_path: &str) -> Result<HashMap<String, IndexEntry>> {
    let f = File::open(index_bz2_path)?;
    let mut dec = BzDecoder::new(BufReader::new(f));
    let mut map = HashMap::new();
    let mut buf = String::new();
    let mut rdr = io::BufReader::new(&mut dec);

    loop {
        buf.clear();
        let n = rdr.read_line(&mut buf)?;
        if n == 0 { break; }
        // line format: offset:page_id:title  (title may contain spaces)
        if let Some((left, title)) = buf.trim_end().split_once(':') {
            if let Some((off_s, id_s)) = left.split_once(':') {
                if let (Ok(offset), Ok(page_id)) = (off_s.parse::<u64>(), id_s.parse::<u64>()) {
                    let norm = normalize_title(title);
                    map.entry(norm.clone()).or_insert(IndexEntry {
                        offset, page_id, title: title.to_string()
                    });
                }
            }
        }
    }
    Ok(map)
}

fn normalize_title(t: &str) -> String {
    t.replace('_', " ")
     .trim()
     .to_string()
}


pub fn extract_article(
    dump_bz2_path: &str,
    offset: u64,
    want_title: &str,
    want_id: u64,
) -> Result<Article> {
    let mut file = File::open(dump_bz2_path)?;
    file.seek(SeekFrom::Start(offset))?;

    // Decompress the ONE bzip2 member starting at `offset`
    let dec = BzDecoder::new(BufReader::new(file));
    let mut reader = Reader::from_reader(BufReader::new(dec));
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut cur_title = String::new();
    let mut cur_id: u64 = 0;
    let mut in_page = false;
    let mut in_title = false;
    let mut in_id = false;
    let mut in_text = false;
    let mut text = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                match e.name().as_ref() {
                    b"page" => { in_page = true; cur_title.clear(); cur_id = 0; text.clear(); }
                    b"title" if in_page => in_title = true,
                    b"id" if in_page && cur_id == 0 => in_id = true, // first <id> inside <page>
                    b"text" if in_page => in_text = true,
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                match e.name().as_ref() {
                    b"page" => {
                        // Check if this is our page
                        if normalize_title(&cur_title) == normalize_title(want_title) || cur_id == want_id {
                            let headings = extract_headings(&text);
                            return Ok(Article {
                                title: cur_title.clone(),
                                page_id: cur_id,
                                wikitext: text.clone(),
                                headings,
                            });
                        }
                        in_page = false;
                    }
                    b"title" => in_title = false,
                    b"id" => in_id = false,
                    b"text" => in_text = false,
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_title { cur_title.push_str(&e.unescape().unwrap_or_default()); }
                else if in_id {
                    if let Ok(v) = e.unescape().unwrap_or_default().parse::<u64>() { cur_id = v; }
                } else if in_text {
                    text.push_str(&e.unescape().unwrap_or_default());
                }
            }
            Ok(Event::Eof) => bail!("Page not found in this stream (title: {want_title})"),
            Err(e) => bail!("XML error: {e}"),
            _ => {}
        }
        buf.clear();
    }
}

fn extract_headings(wikitext: &str) -> Vec<Heading> {
    // Matches headings like "== Heading ==" up to "====== h ======".
    // Rust's regex crate does not support backreferences, so capture left and right '=' separately
    // and verify they are equal length in code. Multiline mode (?m) anchors ^ and $ to lines.
    let re = Regex::new(r"(?m)^(?P<l>={2,6})\s*(?P<h>[^=\n][^\n]*?)\s*(?P<r>={2,6})\s*$").expect("compile heading regex");
    let mut out = Vec::new();
    for m in re.find_iter(wikitext) {
        if let Some(caps) = re.captures(m.as_str()) {
            let l = caps.name("l").map(|m| m.as_str()).unwrap_or("");
            let r = caps.name("r").map(|m| m.as_str()).unwrap_or("");
            if l.len() == r.len() {
                let level = (l.len() as u8).min(6).max(1);
                let text = caps.name("h").map(|m| m.as_str().trim().to_string()).unwrap_or_default();
                out.push(Heading { level, text, byte_start: m.start(), byte_end: m.end() });
            }
        }
    }
    out
}

/// Stream the entire bz2-compressed Wikipedia dump and count pages and matches for a keyword.
/// This does on-the-fly decompression; no need to uncompress to disk.
pub fn scan_dump_for_keyword(dump_bz2_path: &str, keyword: &str, print_matches: bool, show_progress: bool) -> Result<(u64, u64, u64)> {
    let file = File::open(dump_bz2_path)
        .with_context(|| format!("opening dump: {dump_bz2_path}"))?;
    // Total compressed bytes for progress percentage (pre-inflation)
    let total_compressed = file.metadata()?.len();
    let compressed_counter = Arc::new(AtomicU64::new(0));
    let decompressed_counter = Arc::new(AtomicU64::new(0));

    // Wrap file to count compressed bytes read
    let file_counted = CountingReadAtomic::new(file, Arc::clone(&compressed_counter));
    let dec = MultiBzDecoder::new(BufReader::new(file_counted));

    // Wrap decoder to count decompressed bytes read
    let dec_counted = CountingReadAtomic::new(dec, Arc::clone(&decompressed_counter));
    let mut reader = Reader::from_reader(BufReader::new(dec_counted));
    reader.trim_text(true);

    let kw_lower = keyword.to_lowercase();

    let mut buf = Vec::new();
    let mut in_page = false;
    let mut in_title = false;
    let mut in_text = false;
    let mut cur_title = String::new();
    let mut text = String::new();
    let mut page_count: u64 = 0;
    let mut match_count: u64 = 0;
    // Background progress renderer
    let stop = Arc::new(AtomicBool::new(false));
    let progress_handle = if show_progress {
        let stop = Arc::clone(&stop);
        let cc = Arc::clone(&compressed_counter);
        let dc = Arc::clone(&decompressed_counter);
        std::thread::spawn(move || {

            let spinner = [
                "⠁","⠉","⠙","⠹","⠸","⠼",
                "⠾","⠿","⠷","⠧","⠇","⠗",
                "⠟","⠞","⠖","⠆","⠄","⠤",
                "⠠","⠐","⠂"
            ];

            let _zigzag = [
                "⠁","⠃","⠅","⠇","⠍","⠏",
                "⠍","⠇","⠅","⠃","⠁"
            ];

            let _bounce = [
                "⠁","⠃","⠇","⠧","⠷","⠿",
                "⠷","⠧","⠇","⠃","⠁"
            ];

            let _spiral = [
                "⠁","⠃","⠇","⠧","⠷","⠿",
                "⠾","⠼","⠸","⠨","⠈","⠉"
            ];

            let _wave = [
                "⠁","⠉","⠙","⠚","⠒","⠂",
                "⠐","⠠","⠤","⠄","⠆","⠖",
                "⠦","⠤","⠠","⠐","⠂","⠒",
                "⠚","⠙","⠉","⠁"
            ];

            let mut i = 0usize;
            while !stop.load(Ordering::Relaxed) {
                let comp = cc.load(Ordering::Relaxed);
                let decomp = dc.load(Ordering::Relaxed);
                let pct = if total_compressed > 0 { (comp as f64) * 100.0 / (total_compressed as f64) } else { 0.0 };
                let s = spinner[i % spinner.len()];
                i = i.wrapping_add(1);
                print!(
                    "{} {:.3}%  {}/{} (compressed) | {} decompressed\r",
                    s, pct, comp, total_compressed, decomp
                );
                let _ = std::io::Write::flush(&mut std::io::stdout());
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        })
    } else { std::thread::spawn(|| {}) };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                match e.name().as_ref() {
                    b"page" => { in_page = true; cur_title.clear(); text.clear(); }
                    b"title" if in_page => in_title = true,
                    b"text" if in_page => in_text = true,
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                match e.name().as_ref() {
                    b"page" => {
                        page_count += 1;
                        // Case-insensitive contains on page text
                        if !kw_lower.is_empty() {
                            if text.to_lowercase().contains(&kw_lower) {
                                match_count += 1;
                                if print_matches { println!("match: {}", cur_title); }
                            }
                        }
                        in_page = false;
                    }
                    b"title" => in_title = false,
                    b"text" => in_text = false,
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_title { cur_title.push_str(&e.unescape().unwrap_or_default()); }
                else if in_text { text.push_str(&e.unescape().unwrap_or_default()); }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML error while scanning: {e}"),
            _ => {}
        }
        buf.clear();
    }

    // Stop background progress thread and print a final newline
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();
    if show_progress { println!(); }

    let bytes = decompressed_counter.load(Ordering::Relaxed);
    Ok((page_count, match_count, bytes))
}

/// Load a keyword .idx file (title\toffset per line)
fn load_keyword_idx(idx_path: &str) -> Result<HashMap<String, u64>> {
    let f = File::open(idx_path)
        .with_context(|| format!("opening idx: {}", idx_path))?;
    let rdr = BufReader::new(f);
    let mut map = HashMap::new();
    for line in rdr.lines() {
        let line = line?;
        if let Some((title, off_s)) = line.split_once('\t') {
            if let Ok(off) = off_s.parse::<u64>() {
                map.insert(title.to_string(), off);
            }
        }
    }
    Ok(map)
}

fn save_keyword_idx(map: &HashMap<String, u64>, out_path: &str) -> Result<()> {
    let mut f = File::create(out_path)
        .with_context(|| format!("opening idx: {}", out_path))?;
    for (title, off) in map {
        f.write_all(format!("{}\t{}\n", title, off).as_bytes())
            .with_context(|| format!("writing idx: {}", out_path))?;
    }
    Ok(())
}

// tiny CLI demo:
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    // TCP REPL mode: --tcp:PORT or --tcp:HOST:PORT
    if args.len() >= 2 && args[1].starts_with("--tcp:") {
        let addr = &args[1][6..];
        return start_tcp_server(addr);
    }
    if args.len() >= 2 && args[1] == "build-idx" {
        // Usage: wikiscan build-idx <dump.xml.bz2> <index.txt.bz2> <keyword> [--out <file>] [--print]
        if args.len() < 5 {
            bail!("usage: wikiscan build-idx <dump.xml.bz2> <index.txt.bz2> <keyword> [--out <file>] [--print]");
        }
        let dump_path = &args[2];
        let ms_index = &args[3];
        let keyword = &args[4];
        let print_matches = args.iter().any(|a| a == "--print");
        let out_path = args.windows(2).find_map(|w| if w[0] == "--out" { Some(w[1].as_str()) } else { None });
        println!("Building keyword index for '{}'...", keyword);
        let (pages, matches, out_file) = build_keyword_index(dump_path, ms_index, keyword, out_path, print_matches, None)?;
        println!("Scanned pages: {}\nMatches: {}\nWrote: {}", pages, matches, out_file);
        return Ok(());
    }

    if args.len() >= 5 && args[1] == "extract-idx" {
        // Usage: wikiscan extract-idx <dump.xml.bz2> <keyword.idx> <title>
        let dump_path = &args[2];
        let idx_path = &args[3];
        let title = args[4..].join(" "); // allow spaces in title
        let idx = load_keyword_idx(idx_path)?;
        let off = idx.get(&title)
            .with_context(|| format!("title not in idx: {}", title))?;
        let art = extract_article(dump_path, *off, &title, 0)?; // 0 = unknown id, match by title
        println!("Title: {} (#{}), text bytes: {}", art.title, art.page_id, art.wikitext.len());
        for h in &art.headings { println!("  {} {}", "#".repeat(h.level as usize), h.text); }
        return Ok(());
    }

    if args.len() >= 3 {
        // Usage: wikiscan <dump.xml.bz2> <keyword> [--print] [--progress]
        let dump_path = &args[1];
        let keyword = &args[2];
        let print_matches = args.iter().any(|a| a == "--print");
        let show_progress = args.iter().any(|a| a == "--progress");
        println!("Scanning {} for keyword: '{}'...", dump_path, keyword);
        let (pages, matches, bytes) = scan_dump_for_keyword(dump_path, keyword, print_matches, show_progress)?;
        println!("Pages: {}\nMatches: {}\nBytes scanned (decompressed): {}", pages, matches, bytes);
        return Ok(());
    }

    // No args: start interactive session
    start_interactive()
}

// TCP server that spawns a child process per connection and binds the
// accepted socket to the child's stdin/stdout (inetd-style). This allows us
// to reuse the existing interactive REPL without refactoring its I/O now.
fn start_tcp_server(addr: &str) -> Result<()> {
    // Delegate to generic TCP server with our service
    let svc = WikiScanService;
    start_tcp_server_generic(svc, addr)
}
