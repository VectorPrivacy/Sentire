//! An OpenAI-compatible vision backend.
//!
//! llama.cpp's `llama-server` speaks this shape, images included as `image_url`
//! data URIs, so pointing at a hosted endpoint is a different `base_url` and an
//! `Authorization` header rather than a second implementation. Local and remote
//! are config, not architecture.

use std::time::Duration;

use serde_json::{json, Value};
use vector_sdk::vector_core::net::{build_http_client, reqwest};

use super::{Label, Verdict, Vision};
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
You are an image classifier for a chat moderation system. Look at the image and \
answer ONLY with a JSON object mapping each of these labels to a confidence from \
0.0 to 1.0, with no prose and no code fence: ";

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

    fn labels_asked(&self) -> String {
        self.cfg.labels.iter().map(|l| l.name.as_str()).collect::<Vec<_>>().join(", ")
    }
}

impl Vision for OpenAiVision {
    fn model(&self) -> &str {
        &self.cfg.model
    }

    async fn classify(&self, bytes: &[u8], mime: &str) -> Verdict {
        let data_uri = format!("data:{mime};base64,{}", b64(bytes));
        let body = json!({
            "model": self.cfg.model,
            "temperature": 0,
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": format!("{PROMPT}{}", self.labels_asked()) },
                    { "type": "image_url", "image_url": { "url": data_uri } }
                ]
            }]
        });

        let mut req = self.client.post(format!("{}/chat/completions", self.cfg.base_url.trim_end_matches('/'))).json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return Verdict::Unknown(format!("unreachable: {e}")),
        };
        if !resp.status().is_success() {
            return Verdict::Unknown(format!("HTTP {}", resp.status()));
        }
        let value: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => return Verdict::Unknown(format!("unreadable response: {e}")),
        };
        let text = value["choices"][0]["message"]["content"].as_str().unwrap_or_default();
        match parse_labels(text) {
            Some(labels) if labels.is_empty() => Verdict::Clean,
            Some(labels) => Verdict::Flagged(labels),
            None => Verdict::Unknown(format!("unparseable answer: {}", text.chars().take(120).collect::<String>())),
        }
    }
}

/// Pull the label map out of whatever the model wrapped it in. Models fence
/// JSON, prepend "Sure!", and trail explanations; the first balanced object is
/// the answer.
pub fn parse_labels(text: &str) -> Option<Vec<Label>> {
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut end = None;
    for (i, c) in text[start..].char_indices() {
        match c {
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
    let obj: Value = serde_json::from_str(&text[start..end?]).ok()?;
    let map = obj.as_object()?;
    Some(
        map.iter()
            .filter_map(|(k, v)| v.as_f64().map(|s| Label { name: k.clone(), score: s.clamp(0.0, 1.0) as f32 }))
            .collect(),
    )
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
    }

    /// A model that answers with an out-of-range score is clamped, not trusted:
    /// a 4.0 must not sail past a 0.9 threshold as if it meant anything.
    #[test]
    fn scores_are_clamped_into_range() {
        let labels = parse_labels(r#"{"gore": 4.0, "spam_graphic": -1.0}"#).unwrap();
        assert!(labels.iter().all(|l| (0.0..=1.0).contains(&l.score)));
    }
}
