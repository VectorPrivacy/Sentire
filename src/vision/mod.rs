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

    fn cfg(pairs: &[(&str, f32, Gravity)]) -> Vec<crate::config::VisionLabel> {
        pairs
            .iter()
            .map(|(n, t, g)| crate::config::VisionLabel { name: (*n).into(), threshold: *t, gravity: *g })
            .collect()
    }

    fn label(name: &str, score: f32) -> Label {
        Label { name: name.into(), score }
    }

    /// A model can say anything. Nothing it invents may become a conviction:
    /// the operator's list is the only vocabulary that counts.
    #[test]
    fn a_label_the_operator_never_named_is_ignored() {
        let c = cfg(&[("gore", 0.9, Gravity::Grave)]);
        let hits = over_threshold(&[label("something_the_model_made_up", 1.0)], &c);
        assert!(hits.is_empty(), "the model does not get to name the offense");
    }

    #[test]
    fn the_threshold_is_a_bound_and_the_bound_itself_counts() {
        let c = cfg(&[("gore", 0.9, Gravity::Grave)]);
        assert!(over_threshold(&[label("gore", 0.89)], &c).is_empty(), "under the bar is under");
        assert_eq!(over_threshold(&[label("gore", 0.9)], &c).len(), 1, "the bar itself is met");
        assert_eq!(over_threshold(&[label("gore", 1.0)], &c).len(), 1);
    }

    /// The gravest hit speaks for the blob, and ties break on the score — so
    /// the answer does not depend on the order a model happened to list them.
    #[test]
    fn the_worst_hit_comes_first_whatever_order_the_model_used() {
        let c = cfg(&[("mild", 0.1, Gravity::Note), ("awful", 0.1, Gravity::Grave)]);
        let forwards = over_threshold(&[label("mild", 0.99), label("awful", 0.2)], &c);
        let backwards = over_threshold(&[label("awful", 0.2), label("mild", 0.99)], &c);
        assert_eq!(forwards[0].1, Gravity::Grave, "gravity outranks confidence");
        assert_eq!(forwards, backwards, "and order in the answer changes nothing");
    }

    #[test]
    fn equal_gravity_breaks_on_the_higher_score() {
        let c = cfg(&[("a", 0.1, Gravity::Serious), ("b", 0.1, Gravity::Serious)]);
        let hits = over_threshold(&[label("a", 0.3), label("b", 0.8)], &c);
        assert_eq!(hits[0].0.name, "b");
    }

    /// A model answering nonsense must not become a conviction by arithmetic.
    #[test]
    fn absurd_scores_do_not_produce_absurd_answers() {
        let c = cfg(&[("gore", 0.9, Gravity::Grave)]);
        for score in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -1.0, 5.0] {
            let hits = over_threshold(&[label("gore", score)], &c);
            // Whatever it decides, it must not panic and must stay sortable.
            assert!(hits.len() <= 1, "score {score} produced {hits:?}");
        }
        assert!(over_threshold(&[label("gore", f32::NAN)], &c).is_empty(), "NaN is not over a threshold");
    }

    #[test]
    fn nothing_configured_flags_nothing() {
        assert!(over_threshold(&[label("gore", 1.0)], &[]).is_empty());
        assert!(over_threshold(&[], &cfg(&[("gore", 0.9, Gravity::Grave)])).is_empty());
    }

    /// The distinction the whole lane rests on, asserted as a type property.
    #[test]
    fn unknown_is_never_clean() {
        assert_ne!(Verdict::Unknown("timeout".into()), Verdict::Clean);
        assert_ne!(Verdict::Flagged(vec![]), Verdict::Clean);
        // And it round-trips, because it is cached and read back.
        let v = Verdict::Flagged(vec![label("gore", 0.95)]);
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
    }
}
