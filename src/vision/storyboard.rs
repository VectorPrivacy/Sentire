//! A clip becomes one contact sheet, so a still-image model can answer for it.
//!
//! Frames are spread across the WHOLE video rather than its opening seconds:
//! the thing worth catching is rarely in frame one, and an uploader who knows
//! only the first frame is read has been handed the trivial evasion.
//!
//! ffmpeg runs as a CHILD PROCESS, deliberately. This is the one parser
//! Sentinel points at attacker-supplied bytes, and a decoder bug that would
//! take the bot down in-process only kills a child here.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use crate::config::VideoCfg;

/// The sheet that was actually built — never assumed from config, because a
/// clip too short for the full grid gets a smaller one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Board {
    pub cols: u32,
    pub rows: u32,
    /// Seconds between tiles: tile k is at `k * step_secs` in the source.
    pub step_secs: f64,
    /// How much of the clip the sheet spans.
    pub covers_secs: f64,
}

impl Board {
    pub fn tiles(&self) -> u32 {
        self.cols * self.rows
    }
}

/// What a probe could learn about a clip, cheaply.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Probe {
    pub duration_secs: f64,
    /// `None` when the container did not say and no frame rate was given, which
    /// is not the same as zero — it means "spread across the duration blind".
    pub frames: Option<u32>,
}

/// The largest grid the available frames actually fill.
///
/// Partial grids flush with BLACK cells, so a four-frame clip in a 3x2 asks the
/// model to read two holes and bills for the pixels. Never more tiles than
/// frames.
pub fn geometry(frames: Option<u32>, max_cols: u32, max_rows: u32) -> (u32, u32) {
    let (max_cols, max_rows) = (max_cols.max(1), max_rows.max(1));
    // Nothing said: trust the operator's grid and let ffmpeg pad if it must.
    let Some(frames) = frames else { return (max_cols, max_rows) };
    if frames <= 1 {
        return (1, 1);
    }
    let mut best = (1, 1);
    for c in 1..=max_cols {
        for r in 1..=max_rows {
            if c * r <= frames && c * r > best.0 * best.1 {
                best = (c, r);
            }
        }
    }
    best
}

/// Frames per second of SOURCE time that lands `tiles` frames across `span`.
///
/// The last tile sits one step short of the end rather than on it, which is
/// what sampling a span can do without seeking past it.
pub fn sample_fps(span_secs: f64, tiles: u32) -> f64 {
    if !span_secs.is_finite() || span_secs <= 0.0 || tiles == 0 {
        return 1.0;
    }
    (tiles as f64 / span_secs).clamp(0.000_1, 60.0)
}

/// How much of a clip to sample across.
pub fn span_of(duration_secs: f64, max_duration_secs: f64) -> f64 {
    if !duration_secs.is_finite() || duration_secs <= 0.0 {
        return 0.0;
    }
    if max_duration_secs > 0.0 {
        duration_secs.min(max_duration_secs)
    } else {
        duration_secs
    }
}

/// Parse `ffprobe -show_entries` key=value output.
///
/// A missing `avg_frame_rate` AND a missing `nb_frames` means no video stream
/// was found — an audio file wearing a video container, which is not something
/// to hand a vision model.
pub fn parse_probe(out: &str) -> Result<Probe, String> {
    let mut duration = None;
    let mut nb_frames = None;
    let mut fps = None;
    let mut saw_video = false;
    for line in out.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "duration" => duration = v.trim().parse::<f64>().ok(),
            "nb_frames" => {
                saw_video = true;
                nb_frames = v.trim().parse::<u32>().ok();
            }
            "avg_frame_rate" => {
                saw_video = true;
                fps = parse_rational(v.trim());
            }
            _ => {}
        }
    }
    if !saw_video {
        return Err("no video stream".into());
    }
    let duration_secs = duration.unwrap_or(0.0);
    // `nb_frames` is authoritative where the container carries it; otherwise the
    // frame rate and duration estimate it. Both absent leaves it unknown, which
    // `geometry` reads as "use the configured grid" rather than as zero frames.
    let frames = nb_frames.or_else(|| {
        let fps = fps?;
        (duration_secs > 0.0 && fps > 0.0).then(|| (duration_secs * fps).round().max(1.0) as u32)
    });
    Ok(Probe { duration_secs, frames })
}

/// `30/1`, `0/0`, `24000/1001`.
fn parse_rational(s: &str) -> Option<f64> {
    let (n, d) = s.split_once('/')?;
    let (n, d) = (n.trim().parse::<f64>().ok()?, d.trim().parse::<f64>().ok()?);
    (d != 0.0 && n > 0.0).then_some(n / d)
}

/// Deletes its path on drop, so an early return or a panic does not leave a
/// decrypted attachment lying in the temp directory.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Scratch {
    /// Named from the content hash: two handlers judging the same blob would
    /// otherwise race on one path, and a counter is not stable across restarts.
    fn new(dir: &Path, stem: &str, ext: &str) -> Self {
        Scratch(dir.join(format!("sentinel-{stem}.{ext}")))
    }
}

/// Is the tooling actually there? Reports the version so a surprising ffmpeg on
/// PATH is visible at boot rather than inferred from a decode failure later.
pub fn probe_tooling(cfg: &VideoCfg) -> Result<String, String> {
    for bin in [&cfg.ffprobe, &cfg.ffmpeg] {
        let out = std::process::Command::new(bin)
            .arg("-version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => format!("{bin} is not installed or not on PATH"),
                _ => format!("could not run {bin}: {e}"),
            })?;
        if !out.status.success() {
            return Err(format!("{bin} exited {}", out.status));
        }
    }
    let out = std::process::Command::new(&cfg.ffmpeg)
        .arg("-version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("could not run {}: {e}", cfg.ffmpeg))?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.lines().next().unwrap_or("ffmpeg").trim().to_string())
}

/// Build the contact sheet. `Err` is a reason a person can read, and every
/// caller must treat it as unjudged rather than clean.
pub async fn build(bytes: &[u8], content_hash: &str, cfg: &VideoCfg) -> Result<(Vec<u8>, Board), String> {
    let dir = std::env::temp_dir();
    let stem: String = content_hash.chars().take(32).collect();
    let input = Scratch::new(&dir, &stem, "bin");
    let output = Scratch::new(&dir, &stem, "jpg");
    write_private(&input.0, bytes).map_err(|e| format!("could not stage the clip: {e}"))?;

    let probe = probe(&input.0, cfg).await?;
    let span = span_of(probe.duration_secs, cfg.max_duration_secs);
    // No span to sample across: a still wearing a container, or one whose
    // duration the container never recorded. Take its first frame as a 1x1
    // sheet — `-t 0` makes ffmpeg write no output at all.
    let timed = span > 0.0;
    let (cols, rows) = if timed { geometry(probe.frames, cfg.cols, cfg.rows) } else { (1, 1) };
    let tiles = cols * rows;

    let scale = format!("scale={w}:-1:force_original_aspect_ratio=decrease", w = cfg.tile_width.max(16));
    let filter = if timed && tiles > 1 {
        format!("fps={:.6},{scale},tile={cols}x{rows}:color=black", sample_fps(span, tiles))
    } else {
        format!("{scale},tile=1x1")
    };
    let mut cmd = tokio::process::Command::new(&cfg.ffmpeg);
    cmd.arg("-nostdin")
        .arg("-v")
        .arg("error")
        // A crafted container can otherwise name a URL and make Sentinel fetch it.
        .args(["-protocol_whitelist", "file"])
        .args(["-threads", "1"]);
    if timed {
        cmd.args(["-t", &format!("{span:.3}")]);
    }
    cmd.arg("-i")
        .arg(&input.0)
        .args(["-vf", &filter])
        .args(["-frames:v", "1"])
        .args(["-q:v", "4"])
        .arg("-y")
        .arg(&output.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    run(cmd, cfg.timeout_secs, &cfg.ffmpeg).await?;

    let jpeg = std::fs::read(&output.0).map_err(|e| format!("ffmpeg wrote no sheet: {e}"))?;
    if jpeg.is_empty() {
        return Err("ffmpeg wrote an empty sheet".into());
    }
    let step = if timed { span / tiles as f64 } else { 0.0 };
    Ok((jpeg, Board { cols, rows, step_secs: step, covers_secs: span }))
}

async fn probe(path: &Path, cfg: &VideoCfg) -> Result<Probe, String> {
    let mut cmd = tokio::process::Command::new(&cfg.ffprobe);
    cmd.args(["-v", "error"])
        .args(["-select_streams", "v:0"])
        // Metadata only. `-count_frames` decodes the whole file, which is a way
        // to spend an hour of CPU on a clip nobody will ever be shown.
        .args(["-show_entries", "stream=avg_frame_rate,nb_frames:format=duration"])
        .args(["-of", "default=nw=1"])
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = run(cmd, cfg.timeout_secs, &cfg.ffprobe).await?;
    parse_probe(&out)
}

/// Run a child under a wall clock, killing it if it overruns. Returns stdout.
async fn run(mut cmd: tokio::process::Command, timeout_secs: u64, what: &str) -> Result<String, String> {
    cmd.kill_on_drop(true);
    let child = cmd.spawn().map_err(|e| match e.kind() {
        // The common one, and worth its own sentence: an operator who never
        // installed ffmpeg should not have to read an OS error code.
        std::io::ErrorKind::NotFound => format!("{what} is not installed or not on PATH"),
        _ => format!("could not run {what}: {e}"),
    })?;
    let done = tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), child.wait_with_output()).await;
    let out = match done {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err(format!("{what} failed: {e}")),
        Err(_) => return Err(format!("{what} took longer than {timeout_secs}s")),
    };
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        let why = why.lines().next_back().unwrap_or("no reason given");
        return Err(format!("{what}: {}", why.chars().take(160).collect::<String>()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Owner-only, and never through a path an attacker names.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grid_never_has_more_tiles_than_frames() {
        // Black cells cost pixels and ask the model to read holes.
        assert_eq!(geometry(Some(1), 3, 2), (1, 1));
        assert_eq!(geometry(Some(4), 3, 2), (2, 2));
        assert_eq!(geometry(Some(6), 3, 2), (3, 2));
        assert_eq!(geometry(Some(600), 3, 2), (3, 2), "never larger than asked for");
        for frames in 1..40u32 {
            let (c, r) = geometry(Some(frames), 3, 2);
            assert!(c * r <= frames, "{frames} frames got a {c}x{r} grid");
        }
    }

    /// Five frames in a 3x2 takes 2x2 and drops one, rather than 3x2 with a hole.
    #[test]
    fn an_awkward_count_loses_a_frame_rather_than_gaining_a_hole() {
        assert_eq!(geometry(Some(5), 3, 2), (2, 2));
    }

    /// A container that declares nothing is not a container with no frames.
    #[test]
    fn an_unknown_frame_count_keeps_the_configured_grid() {
        assert_eq!(geometry(None, 3, 2), (3, 2));
    }

    #[test]
    fn a_zero_grid_still_yields_one_tile() {
        assert_eq!(geometry(Some(9), 0, 0), (1, 1));
        assert_eq!(geometry(None, 0, 0), (1, 1));
    }

    #[test]
    fn frames_are_spread_across_the_whole_span() {
        // Six tiles over ten seconds is one every 1.67s, not six in the first second.
        let fps = sample_fps(10.0, 6);
        assert!((fps - 0.6).abs() < 1e-9, "{fps}");
    }

    /// A rate that divides by zero, or one so high it decodes every frame of a
    /// long film, is a way to spend the box rather than a sampling plan.
    #[test]
    fn a_degenerate_span_cannot_produce_a_degenerate_rate() {
        for span in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let fps = sample_fps(span, 6);
            assert!(fps.is_finite() && fps > 0.0, "span {span} gave {fps}");
        }
        assert!(sample_fps(0.000_001, 6) <= 60.0, "capped");
        assert!(sample_fps(1e9, 6) > 0.0, "still positive");
        assert_eq!(sample_fps(10.0, 0), 1.0, "no tiles is not a division");
    }

    #[test]
    fn a_long_clip_is_sampled_across_its_cap_not_its_length() {
        assert_eq!(span_of(3600.0, 600.0), 600.0);
        assert_eq!(span_of(60.0, 600.0), 60.0, "short clips are covered whole");
        assert_eq!(span_of(3600.0, 0.0), 3600.0, "zero cap means no cap");
        assert_eq!(span_of(0.0, 600.0), 0.0);
        assert_eq!(span_of(f64::NAN, 600.0), 0.0);
    }

    #[test]
    fn a_probe_reads_frames_and_duration() {
        let p = parse_probe("avg_frame_rate=30/1\nnb_frames=300\nduration=10.000000\n").unwrap();
        assert_eq!(p.frames, Some(300));
        assert!((p.duration_secs - 10.0).abs() < 1e-9);
    }

    /// Some containers carry no `nb_frames`. Rate times duration is the estimate,
    /// and it only has to be good enough to size a six-cell grid.
    #[test]
    fn a_missing_frame_count_is_estimated_from_the_rate() {
        let p = parse_probe("avg_frame_rate=24000/1001\nduration=10.0\n").unwrap();
        assert_eq!(p.frames, Some(240));
    }

    #[test]
    fn a_rate_of_zero_over_zero_is_not_a_frame_count() {
        let p = parse_probe("avg_frame_rate=0/0\nduration=10.0\n").unwrap();
        assert_eq!(p.frames, None, "unknown, which keeps the configured grid");
    }

    /// An audio file in a video container reaches a person rather than a model.
    #[test]
    fn a_stream_with_no_video_is_an_error_not_an_empty_board() {
        assert!(parse_probe("duration=3.000000\n").is_err());
        assert!(parse_probe("").is_err());
    }

    #[test]
    fn a_rational_parses_or_declines() {
        assert_eq!(parse_rational("30/1"), Some(30.0));
        assert_eq!(parse_rational("0/0"), None);
        assert_eq!(parse_rational("30"), None);
        assert_eq!(parse_rational("N/A"), None);
        assert_eq!(parse_rational("-30/1"), None);
    }

    #[test]
    fn a_scratch_file_is_removed_when_it_falls_out_of_scope() {
        let dir = std::env::temp_dir();
        let path = {
            let s = Scratch::new(&dir, "test-cleanup-unit", "bin");
            write_private(&s.0, b"x").unwrap();
            assert!(s.0.exists());
            s.0.clone()
        };
        assert!(!path.exists(), "a decrypted attachment outlived its scope");
    }

    #[cfg(unix)]
    #[test]
    fn a_staged_attachment_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new(&std::env::temp_dir(), "test-perms-unit", "bin");
        write_private(&s.0, b"secret").unwrap();
        let mode = std::fs::metadata(&s.0).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "mode {mode:o} lets other users read a decrypted attachment");
    }

    /// Everything above is arithmetic on numbers ffprobe reported. This is the
    /// only test that proves the command line itself composes into a real sheet.
    /// Skipped rather than failed where ffmpeg is absent: it is optional, and a
    /// machine without it must still be able to run the suite.
    fn ffmpeg_present(cfg: &VideoCfg) -> bool {
        std::process::Command::new(&cfg.ffprobe)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    /// Generate a clip with ffmpeg's own synthetic source, so the fixture is not
    /// a binary checked into the repo.
    fn make_clip(cfg: &VideoCfg, path: &Path, seconds: f64, rate: u32) -> bool {
        std::process::Command::new(&cfg.ffmpeg)
            .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i"])
            .arg(format!("testsrc=duration={seconds}:size=320x240:rate={rate}"))
            .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-y"])
            .arg(path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn jpeg_size(bytes: &[u8]) -> Option<(u32, u32)> {
        // SOF0/SOF2 carry the dimensions; enough to prove the tiling happened.
        let mut i = 2usize;
        while i + 9 < bytes.len() {
            if bytes[i] != 0xFF {
                i += 1;
                continue;
            }
            let marker = bytes[i + 1];
            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
                let h = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
                let w = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
                return Some((w, h));
            }
            i += 2 + len;
        }
        None
    }

    #[tokio::test]
    async fn a_real_clip_becomes_a_real_sheet() {
        let cfg = VideoCfg { tile_width: 64, ..VideoCfg::default() };
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let clip = Scratch::new(&std::env::temp_dir(), "test-e2e-long", "mp4");
        assert!(make_clip(&cfg, &clip.0, 10.0, 30), "fixture");
        let bytes = std::fs::read(&clip.0).unwrap();

        let (jpeg, board) = build(&bytes, "e2elongclip", &cfg).await.unwrap();
        assert_eq!((board.cols, board.rows), (3, 2), "a 300-frame clip fills the grid");
        assert!((board.covers_secs - 10.0).abs() < 0.5, "covers the clip: {board:?}");
        assert!((board.step_secs - 10.0 / 6.0).abs() < 0.1, "tiles are spread: {board:?}");
        let (w, h) = jpeg_size(&jpeg).expect("a JPEG with dimensions");
        assert_eq!(w, 64 * 3, "three tiles wide, got {w}");
        assert!(h > 0 && h < w, "two rows of 4:3 tiles: {w}x{h}");
    }

    /// The case that made the grid adapt: a clip with fewer frames than cells
    /// used to be five black holes and one picture.
    #[tokio::test]
    async fn a_clip_shorter_than_the_grid_gets_a_smaller_grid() {
        let cfg = VideoCfg { tile_width: 64, ..VideoCfg::default() };
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let clip = Scratch::new(&std::env::temp_dir(), "test-e2e-short", "mp4");
        assert!(make_clip(&cfg, &clip.0, 0.4, 10), "fixture");
        let bytes = std::fs::read(&clip.0).unwrap();

        let (jpeg, board) = build(&bytes, "e2eshortclip", &cfg).await.unwrap();
        assert!(board.tiles() <= 4, "four frames cannot fill six cells: {board:?}");
        let (w, _) = jpeg_size(&jpeg).expect("a JPEG");
        assert_eq!(w, 64 * board.cols, "the sheet is as wide as the grid it reports");
    }

    /// An animated GIF is a clip in an image container. A model shown only the
    /// first frame never sees frame fifty, which is the cheapest evasion there
    /// is.
    #[tokio::test]
    async fn an_animated_gif_is_cut_into_a_sheet() {
        let cfg = VideoCfg { tile_width: 64, ..VideoCfg::default() };
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let gif = Scratch::new(&std::env::temp_dir(), "test-e2e-anim", "gif");
        let made = std::process::Command::new(&cfg.ffmpeg)
            .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i"])
            .arg("testsrc=duration=3:size=160x120:rate=8")
            .arg("-y")
            .arg(&gif.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(made, "fixture");
        let bytes = std::fs::read(&gif.0).unwrap();

        let (jpeg, board) = build(&bytes, "e2eanimatedgif", &cfg).await.unwrap();
        assert!(board.tiles() > 1, "24 frames deserve more than one look: {board:?}");
        assert!(jpeg_size(&jpeg).is_some(), "a real JPEG");
    }

    /// The `-t 0` trap: a source whose container records no duration used to be
    /// handed `-t 0.000`, and ffmpeg then wrote no output at all.
    #[tokio::test]
    async fn a_source_with_no_recorded_duration_still_yields_its_first_frame() {
        let cfg = VideoCfg { tile_width: 64, ..VideoCfg::default() };
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let png = Scratch::new(&std::env::temp_dir(), "test-e2e-untimed", "png");
        let made = std::process::Command::new(&cfg.ffmpeg)
            .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i"])
            .arg("testsrc=duration=0.05:size=160x120:rate=20")
            .args(["-frames:v", "1", "-y"])
            .arg(&png.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(made, "fixture");
        let bytes = std::fs::read(&png.0).unwrap();

        let (jpeg, board) = build(&bytes, "e2euntimedstill", &cfg).await.unwrap();
        assert_eq!((board.cols, board.rows), (1, 1), "one frame is one tile: {board:?}");
        let (w, _) = jpeg_size(&jpeg).expect("a JPEG");
        assert_eq!(w, 64, "scaled to the tile width");
    }

    /// An audio file in a video container reaches a person, not a vision model.
    #[tokio::test]
    async fn audio_wearing_a_video_container_is_not_judged() {
        let cfg = VideoCfg::default();
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let clip = Scratch::new(&std::env::temp_dir(), "test-e2e-audio", "m4a");
        let made = std::process::Command::new(&cfg.ffmpeg)
            .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=2"])
            .args(["-c:a", "aac", "-y"])
            .arg(&clip.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(made, "fixture");
        let bytes = std::fs::read(&clip.0).unwrap();
        let err = build(&bytes, "e2eaudioonly", &cfg).await.unwrap_err();
        assert!(err.contains("no video stream"), "{err}");
    }

    /// Bytes that are not a clip at all must come back as a reason, never as a
    /// sheet and never as a panic.
    #[tokio::test]
    async fn rubbish_is_a_reason_not_a_sheet() {
        let cfg = VideoCfg::default();
        if !ffmpeg_present(&cfg) {
            eprintln!("skipped: ffmpeg not installed");
            return;
        }
        let err = build(&vec![0x41u8; 4096], "e2erubbishbytes", &cfg).await.unwrap_err();
        assert!(!err.is_empty(), "a refusal has to say why");
    }

    /// The wall clock is the only thing standing between a decode bomb and a
    /// pinned core.
    /// A stand-in that ignores every argument and hangs, because the real
    /// binaries exit fast on flags they dislike and would never reach the clock.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_child_that_overruns_is_killed() {
        use std::os::unix::fs::PermissionsExt;
        let hang = std::env::temp_dir().join("sentinel-test-hang.sh");
        std::fs::write(&hang, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&hang, std::fs::Permissions::from_mode(0o700)).unwrap();
        let cfg = VideoCfg {
            ffprobe: hang.to_string_lossy().into_owned(),
            timeout_secs: 1,
            ..VideoCfg::default()
        };
        let started = std::time::Instant::now();
        let err = build(b"x", "e2etimeoutcase", &cfg).await.unwrap_err();
        let _ = std::fs::remove_file(&hang);
        assert!(err.contains("longer than"), "{err}");
        assert!(started.elapsed().as_secs() < 20, "the wall clock did not fire");
    }

    #[tokio::test]
    async fn a_missing_ffmpeg_says_so_plainly() {
        let cfg = VideoCfg {
            ffprobe: "sentinel-no-such-binary".into(),
            ffmpeg: "sentinel-no-such-binary".into(),
            ..VideoCfg::default()
        };
        let err = build(b"not a video", "deadbeef", &cfg).await.unwrap_err();
        assert!(err.contains("not installed"), "{err}");
    }
}
