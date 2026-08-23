//! The media lane: Sentinel's own judgement, not the engine's.
//!
//! The frozen wire types have a classifier-shaped hole — `Evidence::Label`,
//! `CitationTarget::Attachment`, `RuleState::NoClassifier` — and nothing fills
//! it. That is correct by design: the engine is a pure function with no I/O and
//! a vision model is I/O. So everything here is Sentinel's alone. It never
//! reaches `proven`, never enters the combinator, and never appears in another
//! client's report. Say so when reporting it; do not dress a model's opinion up
//! as a cross-client verdict.

pub mod openai;

use crate::config::Gravity;

/// One thing a model claims to see, and how sure it says it is.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Label {
    pub name: String,
    /// 0.0..=1.0.
    pub score: f32,
}

/// What a classification came back as.
///
/// `Unknown` is not `Clean`, and the distinction is the whole safety property:
/// a timeout, a refusal, a malformed answer or an exhausted budget must never
/// read as an all-clear. An unreachable model is a reason to ask a person, not
/// a reason to let everything through.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Verdict {
    Clean,
    Flagged(Vec<Label>),
    Unknown(String),
}

#[allow(async_fn_in_trait)]
pub trait Vision {
    /// Classify decrypted bytes — an image, a video, whatever the operator
    /// listed. `mime` comes from the content itself, never from a filename an
    /// uploader chose, and the model decides whether it can read it.
    async fn classify(&self, bytes: &[u8], mime: &str) -> Verdict;
    fn model(&self) -> &str;
}

/// The labels over their thresholds, worst first. Empty means the model looked
/// and found nothing over the bar — which IS a clean answer, unlike silence.
pub fn over_threshold(labels: &[Label], cfg: &[crate::config::VisionLabel]) -> Vec<(Label, Gravity)> {
    let mut hits: Vec<(Label, Gravity)> = labels
        .iter()
        .filter_map(|l| {
            cfg.iter()
                .find(|c| c.name == l.name)
                .filter(|c| l.score >= c.threshold)
                .map(|c| (l.clone(), c.gravity))
        })
        .collect();
    hits.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.score.total_cmp(&a.0.score)));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::VisionLabel;

    fn labels() -> Vec<VisionLabel> {
        vec![
            VisionLabel { name: "gore".into(), threshold: 0.90, gravity: Gravity::Grave },
            VisionLabel { name: "spam_graphic".into(), threshold: 0.85, gravity: Gravity::Serious },
        ]
    }

    #[test]
    fn a_score_under_its_threshold_is_not_a_finding() {
        let seen = [Label { name: "gore".into(), score: 0.89 }];
        assert!(over_threshold(&seen, &labels()).is_empty(), "0.89 against a 0.90 bar is a miss");
        let seen = [Label { name: "gore".into(), score: 0.90 }];
        assert_eq!(over_threshold(&seen, &labels()).len(), 1, "the bar itself counts");
    }

    #[test]
    fn a_label_nobody_configured_is_ignored_however_confident() {
        let seen = [Label { name: "cats".into(), score: 1.0 }];
        assert!(over_threshold(&seen, &labels()).is_empty(), "an operator judges only what they named");
    }

    #[test]
    fn the_gravest_hit_leads() {
        let seen = [
            Label { name: "spam_graphic".into(), score: 0.99 },
            Label { name: "gore".into(), score: 0.91 },
        ];
        let hits = over_threshold(&seen, &labels());
        assert_eq!(hits[0].1, Gravity::Grave, "gravity outranks confidence");
    }

    /// The distinction the whole lane rests on.
    #[test]
    fn an_unreachable_model_is_never_an_all_clear() {
        assert_ne!(Verdict::Unknown("timeout".into()), Verdict::Clean);
    }

    /// A model that answers something OTHER than what it was asked has not
    /// cleared anything. `{}` parsed, filtered to nothing, and read as clean —
    /// then cached by content hash forever. A vision model is steerable by text
    /// drawn inside the image it is looking at, so that is a one-shot bypass.
    #[test]
    fn an_answer_that_skips_the_question_is_not_a_clean_one() {
        let asked = labels();
        let complete = |seen: &[Label]| asked.iter().all(|a| seen.iter().any(|l| l.name == a.name));
        assert!(!complete(&[]), "an empty answer covers nothing");
        assert!(!complete(&[Label { name: "cats".into(), score: 0.9 }]), "nor does an off-topic one");
        assert!(!complete(&[Label { name: "gore".into(), score: 0.0 }]), "nor a partial one");
        assert!(complete(&[
            Label { name: "gore".into(), score: 0.0 },
            Label { name: "spam_graphic".into(), score: 0.0 },
        ]));
    }
}
