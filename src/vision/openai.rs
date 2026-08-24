//! An OpenAI-compatible vision backend.
//!
//! llama.cpp's `llama-server` speaks this shape, images included as `image_url`
//! data URIs, so pointing at a hosted endpoint is a different `base_url` and an
//! `Authorization` header rather than a second implementation. Local and remote
//! are config, not architecture.

use std::time::Duration;

use serde_json::{json, Value};
use vector_sdk::vector_core::net::{build_http_client, reqwest};

use super::{Label, Shown, Verdict, Vision};
use crate::config::VisionCfg;

pub struct OpenAiVision {
    cfg: VisionCfg,
    api_key: Option<String>,
    client: reqwest::Client,
}

/// What the model is asked. A constant rather than a buried string: an operator
/// tunes their community's standards, and a prompt they cannot read is a rule
/// they cannot audit.
pub const PROMPT: &str = "\
You are a media classifier for a chat moderation system. Score the attachment \
against each label below, then describe it.";

/// The answer's shape, stated in the prompt AND enforced by `response_format`
/// where the endpoint supports it. Belt and braces: schema support is uneven
/// across OpenAI-compatible servers, and a model that ignores the instruction
/// is still caught by the parse.
pub const SHAPE: &str = "\
Answer with ONLY a JSON object, no prose and no code fence, of exactly this shape:\n\
{\"labels\": {<every label name>: <number 0.0 to 1.0>}, \"description\": \"<one sentence>\"}\n\
Every label listed must appear in \"labels\". \"description\" is one plain sentence \
describing what the media actually shows, written for a moderator reading a record \
later — state what is there, not whether it breaks a rule.";

/// Said before the labels when the bytes are a contact sheet. Without it the
/// model answers for the first tile: the sheet looks like one picture, and the
/// worst frame of a clip is rarely its opening one.
pub fn storyboard_preamble(board: &super::storyboard::Board) -> String {
    format!(
        "This image is a {cols}x{rows} grid of {n} still frames sampled in order \
         (left to right, top to bottom) from ONE video clip spanning {secs:.0} seconds. \
         It is not {n} separate images. Judge the clip as a whole: if ANY frame shows \
         something, score it for the whole clip. Blank black cells are padding, not content. ",
        cols = board.cols,
        rows = board.rows,
        n = board.tiles(),
        secs = board.covers_secs,
    )
}

impl OpenAiVision {
    pub fn new(cfg: VisionCfg) -> Result<Self, String> {
        let api_key = if cfg.api_key_env.is_empty() {
            None
        } else {
            Some(std::env::var(&cfg.api_key_env).map_err(|_| format!("vision.api_key_env {} is unset", cfg.api_key_env))?)
        };
        let client = build_http_client(Duration::from_secs(cfg.timeout_secs))?;
        Ok(OpenAiVision { cfg, api_key, client })
    }

    /// Each label with the operator's own definition of it. A bare name leaves
    /// the model guessing what a community means by "spam"; a sentence does not.
    fn labels_asked(&self) -> String {
        self.cfg
            .labels
            .iter()
            .map(|l| {
                if l.describe.trim().is_empty() {
                    format!("- {}", l.name)
                } else {
                    format!("- {}: {}", l.name, l.describe.trim())
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The answer shape as a JSON schema, for endpoints that can hold a model to
    /// one. LM Studio and vLLM honour this; llama.cpp and older servers ignore
    /// or reject it, which is why the parse still has to stand on its own.
    fn schema(&self) -> Value {
        let props: serde_json::Map<String, Value> = self
            .cfg
            .labels
            .iter()
            .map(|l| (l.name.clone(), json!({ "type": "number", "minimum": 0.0, "maximum": 1.0 })))
            .collect();
        let required: Vec<&str> = self.cfg.labels.iter().map(|l| l.name.as_str()).collect();
        json!({
            "type": "json_schema",
            "json_schema": {
                "name": "moderation_verdict",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {
                        "labels": {
                            "type": "object",
                            "properties": props,
                            "required": required,
                            "additionalProperties": false
                        },
                        "description": { "type": "string" }
                    },
                    "required": ["labels", "description"],
                    "additionalProperties": false
                }
            }
        })
    }
}

/// Why a call did not produce an answer. Only one case is worth acting on: an
/// endpoint refusing a parameter is worth one retry, everything else is not.
enum Rejected {
    Parameter,
    Other(String),
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::Parameter => write!(f, "the endpoint refused a request parameter"),
            Rejected::Other(s) => write!(f, "{s}"),
        }
    }
}

impl OpenAiVision {
    async fn post(&self, body: &Value) -> Result<Value, Rejected> {
        let mut req = self
            .client
            .post(format!("{}/chat/completions", self.cfg.base_url.trim_end_matches('/')))
            .json(body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req.send().await.map_err(|e| Rejected::Other(format!("unreachable: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            // 400 is the only status a different body could fix.
            if status == reqwest::StatusCode::BAD_REQUEST {
                return Err(Rejected::Parameter);
            }
            return Err(Rejected::Other(format!("HTTP {status}")));
        }
        resp.json().await.map_err(|e| Rejected::Other(format!("unreadable response: {e}")))
    }
}

impl Vision for OpenAiVision {
    fn model(&self) -> &str {
        &self.cfg.model
    }

    async fn classify(&self, bytes: &[u8], shown: Shown<'_>) -> Verdict {
        let data_uri = format!("data:{};base64,{}", shown.mime(), b64(bytes));
        let preamble = match &shown {
            Shown::Still { .. } => String::new(),
            Shown::Storyboard { board, .. } => storyboard_preamble(board),
        };
        let ask = format!("{preamble}{PROMPT}\n{}\n\n{SHAPE}", self.labels_asked());

        // The conversation grows across attempts: the model is shown its own bad
        // answer and told what was wrong with it, which is what makes a second
        // ask worth more than a repeat of the first.
        let mut messages = vec![json!({
            "role": "user",
            "content": [
                { "type": "text", "text": ask },
                // Always an image by the time it reaches here: a clip was cut
                // into a sheet upstream, and anything still unreadable comes
                // back as an error, which reads as unjudged rather than clean.
                { "type": "image_url", "image_url": { "url": data_uri } }
            ]
        })];
        let mut schema_ok = true;
        let mut last = String::from("the model was never asked");

        for attempt in 0..self.cfg.max_attempts.max(1) {
            let mut body = json!({
                "model": self.cfg.model,
                "temperature": 0,
                // A label map is a few dozen tokens. The cap does not stop a
                // model from deliberating, but it bounds the cost: a loop becomes
                // a truncated answer in seconds instead of a held blob slot until
                // the timeout.
                "max_tokens": self.cfg.max_answer_tokens,
                "messages": messages,
            });
            if !self.cfg.reasoning_effort.is_empty() {
                body["reasoning_effort"] = json!(self.cfg.reasoning_effort);
            }
            if schema_ok {
                body["response_format"] = self.schema();
            }

            let value = match self.post(&body).await {
                Ok(v) => v,
                // One unusable field must not cost the classification. Both are
                // dropped rather than guessed at, and the attempt is not spent.
                Err(Rejected::Parameter) if schema_ok || !self.cfg.reasoning_effort.is_empty() => {
                    schema_ok = false;
                    body.as_object_mut().map(|b| b.remove("response_format"));
                    body.as_object_mut().map(|b| b.remove("reasoning_effort"));
                    match self.post(&body).await {
                        Ok(v) => v,
                        Err(e) => return Verdict::Unknown(e.to_string()),
                    }
                }
                Err(e) => return Verdict::Unknown(e.to_string()),
            };

            let text = value["choices"][0]["message"]["content"].as_str().unwrap_or_default();
            match self.read(text) {
                Ok(answer) => {
                    return if answer.labels.iter().all(|l| l.score <= 0.0) {
                        Verdict::Clean { description: answer.description }
                    } else {
                        Verdict::Flagged { labels: answer.labels, description: answer.description }
                    };
                }
                Err(fault) => {
                    last = fault.to_string();
                    if attempt + 1 < self.cfg.max_attempts.max(1) {
                        println!("[media] {} — asking again ({fault})", self.cfg.model);
                        messages.push(json!({ "role": "assistant", "content": text }));
                        messages.push(json!({ "role": "user", "content": fault.correction() }));
                    }
                }
            }
        }
        // Bounded, so this is reachable: a model that never complies leaves the
        // attachment unjudged, which reaches a person rather than passing.
        Verdict::Unknown(last)
    }
}

impl OpenAiVision {
    /// Turn a reply into an answer, or name what is wrong with it.
    fn read(&self, text: &str) -> Result<super::Answer, super::Fault> {
        let Some(obj) = first_object(text) else { return Err(super::Fault::NotJson) };
        // `{"labels": {...}}` is the asked-for shape, but a model that answers
        // with a bare map of scores has still answered — read both rather than
        // spending an attempt on a difference nobody cares about.
        let scores = obj.get("labels").unwrap_or(&obj);
        let labels = as_labels(scores);
        let missing: Vec<String> = self
            .cfg
            .labels
            .iter()
            .filter(|asked| !labels.iter().any(|l| l.name == asked.name))
            .map(|l| l.name.clone())
            .collect();
        if !missing.is_empty() {
            return Err(super::Fault::Missing(missing));
        }
        let description = obj
            .get("description")
            .and_then(|d| d.as_str())
            .map(|d| d.trim())
            .filter(|d| !d.is_empty())
            .map(|d| d.chars().take(400).collect());
        Ok(super::Answer { labels, description })
    }
}

/// The first balanced JSON object in a reply. Models fence JSON, prepend
/// "Sure!", and trail explanations; the object is the answer.
pub fn first_object(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut escaped = false;
    let mut end = None;
    for (i, c) in text[start..].char_indices() {
        // Braces inside a string are not structure. The description field is
        // free text written by a model looking at attacker-supplied media, so
        // it can contain either brace at will.
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(start + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    serde_json::from_str(&text[start..end?]).ok()
}

/// Read a map of label scores. Every value must be a number: `{"gore": "high"}`
/// would otherwise filter to an empty list, which reads as Clean and caches.
pub fn as_labels(scores: &Value) -> Vec<Label> {
    let Some(map) = scores.as_object() else { return Vec::new() };
    let labels: Vec<Label> = map
        .iter()
        .filter_map(|(k, v)| v.as_f64().map(|s| Label { name: k.clone(), score: s.clamp(0.0, 1.0) as f32 }))
        .collect();
    if labels.len() != map.len() {
        return Vec::new();
    }
    labels
}

/// Base64, standard alphabet with padding. Small enough not to earn a
/// dependency.
fn b64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole media lane end to end against a REAL endpoint: a clip becomes a
    /// sheet, the sheet becomes a data URI, the model answers, and the answer
    /// parses into a verdict. Everything else in this file tests a piece.
    ///
    /// Ignored by default because it needs a model. Run it with:
    ///   SENTINEL_TEST_VISION_URL=http://host:1234/v1 \
    ///   SENTINEL_TEST_VISION_MODEL=some-model \
    ///   cargo test --  --ignored --nocapture
    #[tokio::test]
    #[ignore = "needs a live vision endpoint"]
    async fn a_real_clip_reaches_a_real_model_and_comes_back_judged() {
        let (Ok(base_url), Ok(model)) = (
            std::env::var("SENTINEL_TEST_VISION_URL"),
            std::env::var("SENTINEL_TEST_VISION_MODEL"),
        ) else {
            panic!("set SENTINEL_TEST_VISION_URL and SENTINEL_TEST_VISION_MODEL");
        };

        let mut cfg = VisionCfg {
            enabled: true,
            base_url,
            model,
            allow_remote: true,
            timeout_secs: 240,
            ..VisionCfg::default()
        };
        cfg.video.tile_width = 256;
        cfg.labels = vec![
            crate::config::VisionLabel { name: "gore".into(), title: String::new(), describe: String::new(), threshold: 0.9, gravity: crate::config::Gravity::Grave },
            crate::config::VisionLabel {
                name: "sexual_content".into(),
                title: String::new(), describe: String::new(),
                threshold: 0.9,
                gravity: crate::config::Gravity::Grave,
            },
        ];

        // A synthetic clip, so the fixture is not a binary in the repo.
        let clip = std::env::temp_dir().join("sentinel-live-clip.mp4");
        let made = std::process::Command::new(&cfg.video.ffmpeg)
            .args(["-nostdin", "-v", "error", "-f", "lavfi", "-i"])
            .arg("testsrc=duration=6:size=320x240:rate=15")
            .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-y"])
            .arg(&clip)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(made, "could not build the fixture clip");
        let bytes = std::fs::read(&clip).unwrap();
        let _ = std::fs::remove_file(&clip);

        let (sheet, board) = crate::vision::storyboard::build(&bytes, "liveendtoend", &cfg.video)
            .await
            .expect("the clip should cut into a sheet");
        println!("sheet: {}x{} tiles, {} bytes", board.cols, board.rows, sheet.len());
        assert!(board.tiles() > 1, "a 90-frame clip deserves a grid: {board:?}");

        let eyes = OpenAiVision::new(cfg).unwrap();
        let verdict = eyes.classify(&sheet, Shown::Storyboard { mime: "image/jpeg", board }).await;
        println!("verdict: {verdict:?}");

        // A test card is not gore. What matters is that the model ANSWERED:
        // Unknown is the failure this whole path exists to avoid.
        assert!(
            !matches!(verdict, Verdict::Unknown(_)),
            "the model did not produce a usable answer: {verdict:?}"
        );
    }

    #[test]
    fn base64_matches_the_canonical_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        // A PNG magic header, since that is what actually travels.
        assert_eq!(b64(&[0x89, b'P', b'N', b'G']), "iVBORw==");
    }

    /// The parser as the label-reading path uses it, over the same two functions
    /// production calls. A helper rather than a shipped function: nothing but
    /// these tests reads labels without also checking which ones are missing.
    fn parse_labels(text: &str) -> Option<Vec<Label>> {
        let obj = first_object(text)?;
        let scores = obj.get("labels").unwrap_or(&obj);
        let map = scores.as_object()?;
        let labels = as_labels(scores);
        if labels.is_empty() && !map.is_empty() {
            return None;
        }
        Some(labels)
    }

    fn eyes(labels: &[&str]) -> OpenAiVision {
        let cfg = VisionCfg {
            labels: labels
                .iter()
                .map(|n| crate::config::VisionLabel {
                    name: (*n).into(),
                    title: String::new(), describe: String::new(),
                    threshold: 0.9,
                    gravity: crate::config::Gravity::Grave,
                })
                .collect(),
            ..VisionCfg::default()
        };
        OpenAiVision::new(cfg).unwrap()
    }

    #[test]
    fn the_asked_for_shape_reads_scores_and_a_description() {
        let a = eyes(&["gore", "nsfw"])
            .read(r#"{"labels": {"gore": 0.1, "nsfw": 0.95}, "description": "A person on a beach."}"#)
            .unwrap();
        assert_eq!(a.labels.len(), 2);
        assert_eq!(a.description.as_deref(), Some("A person on a beach."));
    }

    /// A model that answers with a bare score map has still answered. Spending
    /// an attempt on a difference nobody acts on is a slower verdict, not a
    /// safer one.
    #[test]
    fn a_bare_score_map_is_still_an_answer() {
        let a = eyes(&["gore"]).read(r#"{"gore": 0.2}"#).unwrap();
        assert_eq!(a.labels.len(), 1);
        assert_eq!(a.description, None);
    }

    /// The fault that matters: `{}` satisfied "every value is a number" and read
    /// as a full all-clear, cached by content hash forever.
    #[test]
    fn a_dropped_label_is_named_rather_than_assumed_zero() {
        let e = eyes(&["gore", "nsfw"]).read(r#"{"labels": {"gore": 0.1}}"#).unwrap_err();
        assert_eq!(e, super::super::Fault::Missing(vec!["nsfw".into()]));
        assert!(e.correction().contains("nsfw"), "the retry has to say what was missing");

        let e = eyes(&["gore"]).read("{}").unwrap_err();
        assert!(matches!(e, super::super::Fault::Missing(_)), "an empty object is not an all-clear");
    }

    #[test]
    fn prose_and_truncation_are_faults_not_verdicts() {
        for text in ["I'm sorry, I can't help with that.", "", r#"{"labels": {"gore": 0."#] {
            let e = eyes(&["gore"]).read(text).unwrap_err();
            assert_eq!(e, super::super::Fault::NotJson, "{text:?}");
            assert!(e.correction().contains("ONLY"), "the retry has to name the fault");
        }
    }

    /// The description is free text a model wrote while looking at
    /// attacker-supplied media, so it can contain either brace at will. Scanning
    /// for a balanced object without tracking strings ends it at the wrong byte.
    #[test]
    fn braces_inside_the_description_do_not_end_the_object() {
        let a = eyes(&["gore"])
            .read(r#"{"labels": {"gore": 0.0}, "description": "A screenshot of code: if (x) { y(); }"}"#)
            .unwrap();
        assert_eq!(a.labels.len(), 1);
        assert!(a.description.unwrap().contains("y();"));
    }

    #[test]
    fn an_escaped_quote_in_the_description_does_not_end_the_string() {
        let a = eyes(&["gore"])
            .read(r#"{"labels": {"gore": 0.0}, "description": "A sign reading \"free\" in red {}"}"#)
            .unwrap();
        assert!(a.description.unwrap().contains("free"));
    }

    /// A model told to write one sentence can write an essay, and it lands in a
    /// strike record a moderator has to read.
    #[test]
    fn a_runaway_description_is_capped_and_blank_is_absent() {
        let long = "x".repeat(5_000);
        let a = eyes(&["gore"])
            .read(&format!(r#"{{"labels": {{"gore": 0.0}}, "description": "{long}"}}"#))
            .unwrap();
        assert_eq!(a.description.unwrap().chars().count(), 400);

        let a = eyes(&["gore"]).read(r#"{"labels": {"gore": 0.0}, "description": "   "}"#).unwrap();
        assert_eq!(a.description, None, "whitespace is not a description");
    }

    #[test]
    fn a_fenced_or_chatty_answer_still_parses() {
        for text in [
            r#"{"gore": 0.1, "spam_graphic": 0.9}"#,
            "```json\n{\"gore\": 0.1, \"spam_graphic\": 0.9}\n```",
            "Sure! Here you go:\n{\"gore\": 0.1, \"spam_graphic\": 0.9}\nHope that helps.",
        ] {
            let labels = parse_labels(text).expect(text);
            assert_eq!(labels.len(), 2, "{text}");
            assert!(labels.iter().any(|l| l.name == "spam_graphic" && (l.score - 0.9).abs() < 1e-6));
        }
    }

    #[test]
    fn nonsense_is_unparseable_rather_than_clean() {
        assert!(parse_labels("I'm sorry, I can't help with that.").is_none());
        assert!(parse_labels("").is_none());
        assert!(parse_labels("{ unbalanced").is_none());
        // The dangerous one: a model answering in words. Filtering these away
        // left an empty list, which reads as a full all-clear.
        assert!(parse_labels(r#"{"gore": "high", "sexual_content": "yes"}"#).is_none());
        assert!(parse_labels(r#"{"gore": 0.1, "sexual_content": "yes"}"#).is_none(), "partly readable is not readable");
    }

    /// A model that answers with an out-of-range score is clamped, not trusted:
    /// a 4.0 must not sail past a 0.9 threshold as if it meant anything.
    #[test]
    fn scores_are_clamped_into_range() {
        let labels = parse_labels(r#"{"gore": 4.0, "spam_graphic": -1.0}"#).unwrap();
        assert!(labels.iter().all(|l| (0.0..=1.0).contains(&l.score)));
    }

    /// The model's text is the least controlled input in the bot. Every shape
    /// below either parses to exactly what it says, or refuses — and refusing
    /// routes to a person, which is the safe direction.
    #[test]
    fn the_parser_reads_what_models_actually_send() {
        let cases: &[(&str, Option<&[(&str, f32)]>)] = &[
            (r#"{"gore":0.9}"#, Some(&[("gore", 0.9)])),
            ("Sure! Here you go:\n```json\n{\"gore\": 0.1}\n```", Some(&[("gore", 0.1)])),
            ("I think:\n{\"gore\": 0.5, \"spam\": 0.25}\nHope that helps!", Some(&[("gore", 0.5), ("spam", 0.25)])),
            ("{}", Some(&[])),
            (r#"{"nested":{"a":1}}"#, None),
            (r#"{"gore":"high"}"#, None),
            (r#"{"gore":0.5,"spam":"lots"}"#, None),
            ("no json at all", None),
            ("{unclosed", None),
            ("", None),
            ("}{", None),
        ];
        for (text, want) in cases {
            let got = parse_labels(text);
            match want {
                None => assert!(got.is_none(), "{text:?} must refuse, got {got:?}"),
                Some(pairs) => {
                    let got = got.unwrap_or_else(|| panic!("{text:?} must parse"));
                    assert_eq!(got.len(), pairs.len(), "{text:?}");
                    for (name, score) in *pairs {
                        let l = got.iter().find(|l| l.name == *name).unwrap_or_else(|| panic!("{name} missing"));
                        assert!((l.score - score).abs() < 1e-6, "{name}: {} vs {score}", l.score);
                    }
                }
            }
        }
    }

    /// Multi-byte text before the JSON must not slice mid-character.
    #[test]
    fn a_multibyte_preamble_does_not_panic() {
        for text in ["日本語です {\"gore\": 0.5}", "😀😀😀{\"gore\":0.5}", "日本語"] {
            let _ = parse_labels(text);
        }
        assert!(parse_labels("日本語です {\"gore\": 0.5}").is_some());
    }

    /// Deeply nested junk must terminate rather than run away.
    #[test]
    fn pathological_input_terminates() {
        let deep = "{".repeat(10_000);
        assert!(parse_labels(&deep).is_none());
        let balanced = format!("{}{}", "{".repeat(500), "}".repeat(500));
        let _ = parse_labels(&balanced);
    }
}
