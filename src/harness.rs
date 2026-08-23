//! An offline community, for tests.
//!
//! Builds engine signals, runs the REAL policy engine over them, and converts
//! the result through the SAME code path the live bot uses
//! (`Verdicts::from_console_report`). Nothing here fakes a verdict: a test that
//! says a word filter convicts is a test that ran the word filter.
//!
//! The clock is an argument and every key is derived from a counter, so a run
//! is byte-identical every time.

use std::collections::BTreeMap;

use vector_sdk::nostr::{Keys, PublicKey, SecretKey, ToBech32};
use vector_sdk::policy::{Policy, Verdicts};
use vector_sdk::vector_core::community::policy::engine::{
    evaluate_as, EvalMode, LoadedPolicy, MemberSignal, MessageSignal, Signals,
};
use vector_sdk::vector_core::community::policy::harness::{console_report, hash_policy_bytes, MemberFacts};
use vector_sdk::vector_core::community::policy::types::{Hash32, MessageId, ModerationReport, SubjectId};

/// A member of the offline community.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Who {
    pub subject: SubjectId,
    seed: u8,
}

/// Deterministic, valid secp256k1 identities. Seed 0 is reserved for the owner.
fn keys(seed: u8) -> Keys {
    let mut bytes = [1u8; 32];
    bytes[31] = seed.wrapping_add(1);
    Keys::new(SecretKey::from_slice(&bytes).expect("valid secret"))
}

impl Who {
    pub fn npub(&self) -> String {
        keys(self.seed).public_key().to_bech32().expect("bech32")
    }
}

/// The one channel every message lands in. Content, not identity — nothing in
/// these tests turns on which channel a message came from.
const CHANNEL: Hash32 = Hash32([7u8; 32]);

/// One hour, in ms — the unit most window arithmetic is written in.
pub const HOUR: u64 = 3_600_000;

/// A community that exists only in memory.
pub struct World {
    owner: SubjectId,
    members: Vec<MemberSignal>,
    messages: Vec<MessageSignal>,
    facts: BTreeMap<String, MemberFacts>,
    next_seed: u8,
    next_msg: u32,
    /// Where `says` puts the next message. The corpus is `at_ms < now_ms`
    /// strictly, so anything said AT the evaluation instant is not yet history
    /// and no rule can see it.
    cursor: u64,
    /// The instant the engine evaluates at.
    pub now_ms: u64,
}

impl World {
    /// A community whose clock starts a week in, so tenure and windows have
    /// room to look backwards without underflowing.
    pub fn new() -> World {
        let owner = keys(0);
        let owner_id = SubjectId(owner.public_key().to_bytes());
        let mut w = World {
            owner: owner_id,
            members: vec![],
            messages: vec![],
            facts: BTreeMap::new(),
            next_seed: 1,
            next_msg: 0,
            cursor: 30 * 24 * HOUR - HOUR,
            now_ms: 30 * 24 * HOUR,
        };
        w.push_member(owner_id, 0, true, 0, None);
        w
    }

    fn push_member(&mut self, subject: SubjectId, seed: u8, is_staff: bool, lifetime: u64, joined: Option<u64>) {
        let npub = keys(seed).public_key().to_bech32().expect("bech32");
        self.members.push(MemberSignal {
            subject,
            joined_at_ms: joined,
            roles: vec![],
            is_staff,
            lifetime_messages: lifetime,
            first_post_ms: joined,
        });
        self.facts.insert(
            npub,
            MemberFacts {
                joined_at_ms: joined.unwrap_or(0),
                invite_label: None,
                messages: lifetime,
                distinct: lifetime,
                tenure_secs: joined.map(|j| (self.now_ms.saturating_sub(j)) / 1000).unwrap_or(0),
                last_secs: 0,
                is_owner: subject == self.owner,
                is_admin: is_staff,
                is_me: false,
            },
        );
    }

    /// Someone who joined just now and has said nothing. The default shape of
    /// a raider.
    pub fn stranger(&mut self) -> Who {
        self.member_joined(self.now_ms, 0)
    }

    /// Someone with history: joined `ago_ms` back, with `lifetime` messages
    /// behind them. This is what earns a Trusted shield.
    pub fn regular(&mut self, ago_ms: u64, lifetime: u64) -> Who {
        let joined = self.now_ms.saturating_sub(ago_ms);
        self.member_joined(joined, lifetime)
    }

    fn member_joined(&mut self, joined: u64, lifetime: u64) -> Who {
        let seed = self.next_seed;
        self.next_seed = self.next_seed.checked_add(1).expect("under 255 members");
        let subject = SubjectId(keys(seed).public_key().to_bytes());
        self.push_member(subject, seed, false, lifetime, Some(joined));
        Who { subject, seed }
    }

    /// A moderator: the engine shields them because they hold permissions.
    pub fn staff(&mut self) -> Who {
        let seed = self.next_seed;
        self.next_seed = self.next_seed.checked_add(1).expect("under 255 members");
        let subject = SubjectId(keys(seed).public_key().to_bytes());
        let joined = self.now_ms.saturating_sub(30 * 24 * HOUR);
        self.push_member(subject, seed, true, 500, Some(joined));
        Who { subject, seed }
    }

    /// The owner, whom nothing may ever convict.
    pub fn owner(&self) -> Who {
        Who { subject: self.owner, seed: 0 }
    }

    /// Say something. Each call advances a second, so ordering is the order
    /// written and everything lands inside the corpus.
    pub fn says(&mut self, who: Who, text: &str) -> MessageId {
        self.says_tagging(who, text, 0)
    }

    /// Say something with p-tags — the only thing that counts as a mention.
    pub fn says_tagging(&mut self, who: Who, text: &str, mentions: u32) -> MessageId {
        let at = self.cursor;
        assert!(at < self.now_ms, "the harness ran past its evaluation instant; use said_at for a long history");
        self.cursor += 1000;
        self.said_at(who, text, at, mentions)
    }

    /// Say something at an explicit instant, for window and rate arithmetic.
    pub fn said_at(&mut self, who: Who, text: &str, at_ms: u64, mentions: u32) -> MessageId {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&self.next_msg.to_be_bytes());
        self.next_msg += 1;
        let id = MessageId(id);
        self.messages.push(MessageSignal {
            id,
            author: who.subject,
            channel: CHANNEL,
            at_ms,
            text: text.to_string(),
            mentions,
        });
        id
    }

    /// Run the real engine over everything said so far.
    pub fn report(&self, policy: &Policy) -> ModerationReport {
        let json = policy.clone().build().expect("policy builds");
        let doc = serde_json::from_str(&json).expect("policy round-trips");
        let loaded = LoadedPolicy { hash: hash_policy_bytes(json.as_bytes()), policy: doc, activated_at: None };
        evaluate_as(&self.signals(), &[loaded], &[], self.now_ms, EvalMode::Admin)
    }

    /// The verdicts a bot would receive, through the live conversion.
    pub fn verdicts(&self, policy: &Policy) -> Verdicts {
        let report = self.report(policy);
        Verdicts::from_console_report(&console_report(&report, &self.facts, self.now_ms / 1000))
    }

    fn signals(&self) -> Signals {
        // A confirmed range that spans everything: coverage gating is a
        // separate concern and a test that trips it is testing the wrong thing.
        let from = 0;
        let to = self.now_ms;
        Signals {
            owner: self.owner,
            members: self.members.clone(),
            messages: self.messages.clone(),
            channels: vec![CHANNEL],
            relays: vec![],
            requested_from: from,
            requested_to: to,
            confirmed_from: from,
            confirmed_to: to,
            roster_version: Hash32([0u8; 32]),
        }
    }
}

/// The npub of a verdict, shortened the way the logs do.
pub fn find<'a>(vs: &'a Verdicts, who: &Who) -> Option<&'a vector_sdk::policy::Verdict> {
    let npub = who.npub();
    vs.all().find(|v| v.npub == npub)
}

/// Sanity: `PublicKey` parsing is what console_report needs to emit a member at
/// all, so a broken key derivation would silently empty every test below.
pub fn assert_derivable(seed: u8) {
    let k = keys(seed);
    assert!(PublicKey::from_slice(&k.public_key().to_bytes()).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Gravity, WordRule, LinkRule};
    use crate::rules;

    /// A config whose only rule is one word list, so a conviction can only have
    /// come from it.
    fn word_policy(id: &str, patterns: &[&str], gravity: Gravity) -> Policy {
        let mut cfg = Config::default();
        cfg.rules.words = vec![WordRule {
            id: id.into(),
            patterns: patterns.iter().map(|s| s.to_string()).collect(),
            gravity,
        }];
        rules::compile(&cfg.for_community("")).expect("a word rule is a rule")
    }

    fn link_policy(id: &str, domains: &[&str], gravity: Gravity) -> Policy {
        let mut cfg = Config::default();
        cfg.rules.links = vec![LinkRule {
            id: id.into(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            gravity,
        }];
        rules::compile(&cfg.for_community("")).expect("a link rule is a rule")
    }

    #[test]
    fn every_derived_identity_is_a_real_pubkey() {
        // console_report drops any subject whose key will not parse, which
        // would empty every test below while they all still passed.
        for seed in 0..12u8 {
            assert_derivable(seed);
        }
    }

    /// The whole text lane, end to end: config -> policy -> engine -> verdict.
    #[test]
    fn a_word_rule_convicts_the_member_who_said_the_word() {
        let mut w = World::new();
        let rude = w.stranger();
        let quiet = w.stranger();
        w.says(rude, "you are a badword and I mean it");
        w.says(quiet, "good morning everyone");

        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Serious));

        let v = find(&vs, &rude).expect("the speaker is reported");
        assert!(!v.findings.is_empty(), "a word rule that convicts nobody is not a word filter");
        assert!(v.findings.iter().any(|f| f.rule_id == "rude"), "under the rule the operator named");
        assert!(
            v.findings.iter().all(|f| f.is_proven()),
            "a word match is replayable, so it is deterministic evidence and may be charged"
        );

        let q = find(&vs, &quiet).expect("every member is reported");
        assert!(q.findings.is_empty(), "saying nothing wrong convicts nobody");
    }

    #[test]
    fn a_word_rule_is_token_anchored_by_default() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "I grew up in Scunthorpe and it was fine");

        let vs = w.verdicts(&word_policy("rude", &["cunt"], Gravity::Grave));
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.is_empty(), "a bare pattern matches a TOKEN, not a substring");
    }

    #[test]
    fn a_star_relaxes_the_anchor_on_purpose() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "that is unbelievablybad news");

        let vs = w.verdicts(&word_policy("rude", &["*bad*"], Gravity::Minor));
        let v = find(&vs, &who).expect("reported");
        assert!(!v.findings.is_empty(), "an operator who asks for a substring gets one");
    }

    #[test]
    fn the_owner_is_never_convicted() {
        let mut w = World::new();
        let owner = w.owner();
        w.says(owner, "badword badword badword");

        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Grave));
        let v = find(&vs, &owner).expect("the owner is reported");
        assert_eq!(v.shield, "protected", "the owner is never Sentinel's to judge");
    }

    #[test]
    fn staff_are_shielded_by_their_permissions() {
        let mut w = World::new();
        let mod_ = w.staff();
        w.says(mod_, "badword");

        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Grave));
        let v = find(&vs, &mod_).expect("reported");
        assert_eq!(v.shield, "protected", "holding moderation permissions is a shield");
    }

    #[test]
    fn a_link_rule_convicts_on_a_listed_domain() {
        let mut w = World::new();
        let spammer = w.stranger();
        w.says(spammer, "free coins at https://evil.example/claim right now");

        let vs = w.verdicts(&link_policy("scam", &["evil.example"], Gravity::Grave));
        let v = find(&vs, &spammer).expect("reported");
        assert!(v.findings.iter().any(|f| f.rule_id == "scam"), "the domain the operator listed");
    }

    #[test]
    fn an_unlisted_domain_convicts_nobody() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "my blog is at https://harmless.example/post");

        let vs = w.verdicts(&link_policy("scam", &["evil.example"], Gravity::Grave));
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.is_empty(), "a link rule is a list, not a link ban");
    }

    /// The operator's gravity has to survive the whole trip, or Sentinel
    /// sentences on somebody else's scale.
    #[test]
    fn the_configured_gravity_reaches_the_finding() {
        for (gravity, severity) in [
            (Gravity::Note, "notice"),
            (Gravity::Minor, "minor"),
            (Gravity::Serious, "major"),
            (Gravity::Grave, "severe"),
        ] {
            let mut w = World::new();
            let who = w.stranger();
            w.says(who, "badword");
            let vs = w.verdicts(&word_policy("rude", &["badword"], gravity));
            let v = find(&vs, &who).expect("reported");
            let f = v.findings.iter().find(|f| f.rule_id == "rude").expect("convicted");
            assert_eq!(f.severity, severity, "{gravity:?} must arrive as {severity}");
        }
    }

    /// The discovery that made `charges` a function: `Verdict::is_proven` is a
    /// SCORE, and a light rule never reaches it. Gating the sweep on it meant
    /// the ledger stayed empty for exactly the offenses the ladder exists to
    /// accumulate.
    #[test]
    fn a_light_rule_still_charges_though_its_score_never_reaches_actionable() {
        let mut w = World::new();
        let who = w.stranger();
        for _ in 0..10 {
            w.says(who, "badword");
        }
        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Note));
        let v = find(&vs, &who).expect("reported");

        assert!(!v.is_proven(), "ten notes is still not enough to act on unattended — that is the engine's call");
        assert!(!v.findings.is_empty(), "but it IS evidence");

        let cfg = Config::default();
        let charged = crate::review::charges(v, &cfg.for_community(""));
        assert!(!charged.is_empty(), "and the ledger records it, or a note-gravity rule is decoration");
    }

    /// Sentinel's own scale, not the engine's: the same finding is worth what
    /// the operator said it is worth.
    #[test]
    fn the_operators_gravity_decides_what_a_charge_is_worth() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "badword");

        let mut light = Config::default();
        light.rules.words = vec![WordRule { id: "rude".into(), patterns: vec!["badword".into()], gravity: Gravity::Note }];
        let mut heavy = Config::default();
        heavy.rules.words = vec![WordRule { id: "rude".into(), patterns: vec!["badword".into()], gravity: Gravity::Grave }];

        let vs_light = w.verdicts(&rules::compile(&light.for_community("")).unwrap());
        let vs_heavy = w.verdicts(&rules::compile(&heavy.for_community("")).unwrap());

        let cl: u32 = crate::review::charges(find(&vs_light, &who).unwrap(), &light.for_community("")).iter().map(|c| c.worth).sum();
        let ch: u32 = crate::review::charges(find(&vs_heavy, &who).unwrap(), &heavy.for_community("")).iter().map(|c| c.worth).sum();
        assert!(ch > cl, "a grave offense must cost more than a note: {ch} vs {cl}");
    }

    /// One offense billed once. A content rule convicts per message AND per
    /// window over the same citations.
    #[test]
    fn one_offense_is_not_billed_at_both_scopes() {
        let mut w = World::new();
        let who = w.stranger();
        for _ in 0..3 {
            w.says(who, "badword");
        }
        let cfg = Config::default();
        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Serious));
        let v = find(&vs, &who).expect("reported");

        assert!(v.findings.len() > 1, "the engine convicted at both scopes, which is what this guards");
        let charged = crate::review::charges(v, &cfg.for_community(""));
        let ids: std::collections::HashSet<&str> = charged.iter().map(|c| c.conviction.as_str()).collect();
        assert_eq!(ids.len(), charged.len(), "no id is charged twice");
        assert_eq!(charged.len(), 3, "three messages, three charges — not three plus a window rung");
    }
}
