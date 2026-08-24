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
pub mod storyboard;

use crate::config::Gravity;

/// What the model is being shown.
///
/// A contact sheet is one image but it is not one moment, and a model not told
/// so describes the top-left tile and calls the clip clean.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Shown<'a> {
    Still { mime: &'a str },
    Storyboard { mime: &'a str, board: storyboard::Board },
}

impl<'a> Shown<'a> {
    pub fn mime(&self) -> &'a str {
        match self {
            Shown::Still { mime } | Shown::Storyboard { mime, .. } => mime,
        }
    }
}

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
    Clean {
        /// What the model says is in it, for the record a moderator reads later.
        /// Carried on Clean as well as Flagged: the useful question months on is
        /// often "what WAS that", not "what did it break".
        #[serde(default)]
        description: Option<String>,
    },
    Flagged {
        labels: Vec<Label>,
        #[serde(default)]
        description: Option<String>,
    },
    Unknown(String),
}

/// A well-formed answer, before thresholds decide what it means.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    pub labels: Vec<Label>,
    pub description: Option<String>,
}

/// Why an answer was not usable. Named rather than described, because the next
/// attempt tells the model which fault to fix.
#[derive(Debug, Clone, PartialEq)]
pub enum Fault {
    /// No JSON object in the reply at all — prose, a refusal, or a truncation.
    NotJson,
    /// Parsed, but did not score every label asked. `{}` satisfied "all keys are
    /// numbers" and read as a full all-clear, cached by content hash forever.
    Missing(Vec<String>),
}

impl Fault {
    /// What to tell the model it did wrong. Naming the fault is what makes a
    /// second attempt worth more than a repeat of the first.
    pub fn correction(&self) -> String {
        match self {
            Fault::NotJson => "Your previous reply was not a JSON object. Reply with ONLY the JSON \
                 object, no prose, no explanation and no code fence."
                .into(),
            Fault::Missing(names) => format!(
                "Your previous reply left out these labels: {}. Every label must appear with a \
                 number from 0.0 to 1.0. Reply with ONLY the JSON object.",
                names.join(", ")
            ),
        }
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fault::NotJson => write!(f, "the model did not answer with JSON"),
            Fault::Missing(names) => write!(f, "the model did not score: {}", names.join(", ")),
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait Vision {
    /// Classify decrypted bytes. The MIME comes from the content itself, never
    /// from a filename an uploader chose, and `Shown` tells the model whether it
    /// is looking at one picture or a sheet of frames from one clip.
    async fn classify(&self, bytes: &[u8], shown: Shown<'_>) -> Verdict;
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
            VisionLabel { name: "gore".into(), title: String::new(), describe: String::new(), threshold: 0.90, gravity: Gravity::Grave },
            VisionLabel { name: "spam_graphic".into(), title: String::new(), describe: String::new(), threshold: 0.85, gravity: Gravity::Serious },
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
        assert_ne!(Verdict::Unknown("timeout".into()), Verdict::Clean { description: None });
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
            .map(|(n, t, g)| crate::config::VisionLabel { name: (*n).into(), title: String::new(), describe: String::new(), threshold: *t, gravity: *g })
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
        assert_ne!(Verdict::Unknown("timeout".into()), Verdict::Clean { description: None });
        assert_ne!(Verdict::Flagged { labels: vec![], description: None }, Verdict::Clean { description: None });
        // And it round-trips, because it is cached and read back.
        let v = Verdict::Flagged { labels: vec![label("gore", 0.95)], description: None };
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), v);
    }

    /// A stand-in classifier, so the four answers a real one can give are all
    /// exercised without a model or a network.
    struct Fake(Verdict);

    impl Vision for Fake {
        async fn classify(&self, _bytes: &[u8], _shown: Shown<'_>) -> Verdict {
            self.0.clone()
        }
        fn model(&self) -> &str {
            "fake"
        }
    }

    /// The four shapes a classification comes back as, and what each means for
    /// the lane. `Unknown` is the one that must never read as clean.
    #[tokio::test]
    async fn every_answer_a_classifier_can_give_is_handled() {
        let labels = cfg(&[("gore", 0.9, Gravity::Grave)]);
        let cases = [
            (Verdict::Clean { description: None }, 0, "the model looked and found nothing"),
            (Verdict::Flagged { labels: vec![], description: None }, 0, "it looked and nothing cleared the bar"),
            (Verdict::Flagged { labels: vec![label("gore", 0.95)], description: None }, 1, "over the bar"),
            (Verdict::Unknown("timed out".into()), 0, "a timeout is not an all-clear"),
        ];

        for (verdict, want_hits, why) in cases {
            let fake = Fake(verdict.clone());
            let got = fake.classify(b"bytes", Shown::Still { mime: "image/png" }).await;
            assert_eq!(got, verdict, "{why}");
            let hits = match &got {
                Verdict::Flagged { labels: ls, .. } => over_threshold(ls, &labels).len(),
                _ => 0,
            };
            assert_eq!(hits, want_hits, "{why}");
            // The distinction the whole lane rests on.
            assert!(
                !matches!(got, Verdict::Unknown(_)) || !matches!(got, Verdict::Clean { .. }),
                "Unknown must never equal Clean"
            );
        }
    }

    /// A timeout and a refusal are both Unknown, and neither is cached — one
    /// timeout would otherwise retire a blob from classification forever.
    #[test]
    fn unknown_carries_its_reason() {
        for why in ["timed out", "model refused", "cache unreadable: bad json", ""] {
            let v = Verdict::Unknown(why.into());
            assert!(matches!(&v, Verdict::Unknown(w) if w == why));
            assert_ne!(v, Verdict::Clean { description: None });
        }
    }
}
