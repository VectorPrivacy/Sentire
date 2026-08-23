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

/// Everything Sentinel would do about one member, with no network anywhere:
/// the real engine, the real charging rule, a real ledger, the real ladder.
///
/// The only thing missing is the act itself, which is the one part that needs
/// a relay. A test that says "three slurs reach a kick" is a test that ran
/// every step between the words and the kick.
pub struct Pipeline {
    pub cfg: crate::config::Config,
    pub store: crate::store::Store,
    pub powers: crate::policy::Powers,
    /// Successive polls are successive instants. A real sweep runs every 90
    /// seconds, and the ladder reads WHEN an answer was given.
    clock: std::cell::Cell<u64>,
}

impl Pipeline {
    pub fn new(cfg: crate::config::Config) -> Pipeline {
        Pipeline {
            cfg,
            store: crate::store::tests::mem(),
            powers: crate::policy::Powers { hide: true, kick: true, ban: true },
            clock: std::cell::Cell::new(0),
        }
    }

    /// The instant this poll runs at, ninety seconds after the last.
    fn tick(&self, floor: u64) -> u64 {
        let next = self.clock.get().max(floor) + 90_000;
        self.clock.set(next);
        next
    }

    fn policy(&self) -> crate::policy::CommunityPolicy {
        self.cfg.for_community("")
    }

    /// Feed one evaluation in: charge what it convicts, and answer for it.
    ///
    /// Returns the rung, having recorded it — so calling this twice models two
    /// polls, and a second call with no new evidence must answer nothing.
    pub fn poll(&self, w: &World, policy: &Policy, who: &Who) -> Option<crate::config::Response> {
        let vs = w.verdicts(policy);
        let Some(v) = find(&vs, who) else { return None };
        self.answer(v, self.tick(w.now_ms))
    }

    /// The same, for a verdict reached some other way (a media lane finding).
    pub fn answer(&self, v: &vector_sdk::policy::Verdict, now: u64) -> Option<crate::config::Response> {
        let p = self.policy();
        for c in crate::review::charges(v, &p) {
            self.store.record("c", &v.npub, &c.conviction, c.worth, now, &c.evidence).unwrap();
        }
        let strikes = self.store.strikes("c", &v.npub).unwrap();
        let powers = self.powers;
        let rung = crate::act::select_rung(&p, |r| powers.can_deliver(r), &self.store, "c", &v.npub, &strikes, now)
            .unwrap()?;

        // The gate every lane passes through, with the facts a live pass has.
        let facts = crate::adjudicate::Facts {
            shield: &v.shield,
            acted_this_pass: 0,
            acted_this_hour: self.store.actions_last_hour("c", now).unwrap(),
            subjects_this_hour: self.store.subjects_actioned_last_hour("c", now, &v.npub).unwrap(),
            roster: 50,
            is_me: false,
        };
        match crate::adjudicate::adjudicate(&p, powers, &facts, rung) {
            crate::adjudicate::Sentence::Carry { response, .. } => {
                // After the strikes it answered, as `enforce` records it.
                self.store.log_action("c", &v.npub, response.name(), now + 1, "").unwrap();
                Some(response)
            }
            _ => None,
        }
    }

    pub fn total(&self, npub: &str, now: u64) -> u32 {
        let strikes = self.store.strikes("c", npub).unwrap();
        crate::ladder::total(&strikes, now, self.policy().ladder.decay_half_life_hours)
    }
}

/// The engine's own raid defaults, which every community gets without asking.
/// Sentinel does not compile these; it reads what they convict.
pub fn default_policy() -> Policy {
    let doc = vector_sdk::vector_core::community::policy::harness::default_policy();
    let json = serde_json::to_string(&doc).expect("the defaults serialize");
    Policy::from_json(&json).expect("and round-trip")
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
pub(crate) mod tests {
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

    fn armed() -> Config {
        toml::from_str("[arm]\nwarn = true\ndelete = true\nkick = true\nban = true").unwrap()
    }

    /// The headline claim, end to end and offline: words in, a sentence out.
    #[test]
    fn a_word_rule_reaches_a_warning_through_the_whole_pipeline() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "badword");

        let p = Pipeline::new(armed());
        let rung = p.poll(&w, &word_policy("rude", &["badword"], Gravity::Grave), &who);
        assert_eq!(rung, Some(crate::config::Response::Warn), "the first answer is always a warning");
    }

    /// The bug three reviews found, proven through the real engine rather than
    /// a hand-built verdict: re-reading the same message must answer nothing.
    #[test]
    fn twenty_polls_over_one_message_produce_one_sentence() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "badword");
        let policy = word_policy("rude", &["badword"], Gravity::Grave);

        let p = Pipeline::new(armed());
        assert_eq!(p.poll(&w, &policy, &who), Some(crate::config::Response::Warn));
        for poll in 1..=20 {
            assert_eq!(p.poll(&w, &policy, &who), None, "poll {poll} answered an answered offense");
        }
    }

    /// And offending again does climb.
    #[test]
    fn offending_again_climbs_one_rung() {
        let policy = word_policy("rude", &["badword"], Gravity::Grave);
        let p = Pipeline::new(armed());
        let mut w = World::new();
        let who = w.stranger();

        w.says(who, "badword");
        assert_eq!(p.poll(&w, &policy, &who), Some(crate::config::Response::Warn));
        w.says(who, "badword again");
        assert_eq!(p.poll(&w, &policy, &who), Some(crate::config::Response::DeleteAndWarn));
        w.says(who, "badword once more");
        assert_eq!(p.poll(&w, &policy, &who), Some(crate::config::Response::Kick));
    }

    /// Forgiveness is built in: the same offenses spread out do not reach the
    /// rung they reach in a burst.
    #[test]
    fn the_same_offenses_a_month_apart_do_not_reach_a_kick() {
        let policy = word_policy("rude", &["badword"], Gravity::Minor);
        let p = Pipeline::new(armed());

        // Three in a burst.
        let mut burst = World::new();
        let a = burst.stranger();
        for _ in 0..3 {
            burst.says(a, "badword");
        }
        let hot = p.poll(&burst, &policy, &a);

        // The same three, decayed by a month of half-lives.
        let cold = Pipeline::new(armed());
        let mut old = World::new();
        let b = old.stranger();
        for i in 0..3u64 {
            let at = old.now_ms - (30 - i * 7) * 24 * HOUR;
            old.said_at(b, "badword", at, 0);
        }
        let cool = cold.poll(&old, &policy, &b);

        assert!(hot.is_some(), "a burst answers to something");
        assert!(
            cool.is_none() || cool <= hot,
            "the same words spread out must never answer harder: {cool:?} vs {hot:?}"
        );
    }

    /// A shielded member is spared at the gate, however loud the evidence.
    #[test]
    fn the_owner_is_spared_by_the_gate_not_merely_unconvicted() {
        let mut w = World::new();
        let owner = w.owner();
        for _ in 0..10 {
            w.says(owner, "badword");
        }
        let p = Pipeline::new(armed());
        assert_eq!(p.poll(&w, &word_policy("rude", &["badword"], Gravity::Grave), &owner), None);
    }

    /// Nothing armed means nothing decided, but the ledger still fills — which
    /// is what lets an operator watch the run they are about to arm.
    #[test]
    fn a_dry_run_records_what_it_would_have_done() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "badword");

        let p = Pipeline::new(Config::default());
        let rung = p.poll(&w, &word_policy("rude", &["badword"], Gravity::Grave), &who);
        assert_eq!(rung, Some(crate::config::Response::Warn), "the decision is reached either way");
        assert!(p.total(&who.npub(), w.now_ms) > 0, "and the strike is on file");
    }

    /// Two members are two ledgers.
    #[test]
    fn one_members_strikes_never_answer_for_another() {
        let mut w = World::new();
        let noisy = w.stranger();
        let quiet = w.stranger();
        for _ in 0..5 {
            w.says(noisy, "badword");
        }
        w.says(quiet, "good morning");

        let policy = word_policy("rude", &["badword"], Gravity::Grave);
        let p = Pipeline::new(armed());
        assert!(p.poll(&w, &policy, &noisy).is_some());
        assert_eq!(p.poll(&w, &policy, &quiet), None, "saying nothing wrong answers to nothing");
        assert_eq!(p.total(&quiet.npub(), w.now_ms), 0);
    }

    fn rules_policy(f: impl FnOnce(&mut crate::config::Rules)) -> Policy {
        let mut cfg = Config::default();
        f(&mut cfg.rules);
        rules::compile(&cfg.for_community("")).expect("a rule is a rule")
    }

    /// Every rule type the operator can switch on has to actually convict, or
    /// the config field is decoration.
    /// The rung ladder starts at ONE hit, so a rate rule and a repetition rule
    /// convict a member for their first message unless a threshold is set.
    /// Found live: one test post produced sixteen strikes across three rules.
    #[test]
    fn a_rate_rule_does_not_convict_a_member_for_speaking_once() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "hello everyone");

        let policy = rules_policy(|r| {
            r.rate = Some(crate::config::RateRule {
                enabled: true,
                per_secs: 60,
                messages: 10,
                gravity: Gravity::Minor,
            })
        });
        let vs = w.verdicts(&policy);
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.is_empty(), "one message in a minute is a member talking: {:?}", v.findings);
    }

    #[test]
    fn a_repetition_rule_does_not_convict_a_single_message() {
        let mut w = World::new();
        let who = w.stranger();
        w.says(who, "just the one message");

        let policy = rules_policy(|r| {
            r.repetition = Some(crate::config::ToggleRule { enabled: true, times: 4, gravity: Gravity::Minor })
        });
        let vs = w.verdicts(&policy);
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.is_empty(), "a message does not repeat itself: {:?}", v.findings);
    }

    #[test]
    fn a_rate_rule_convicts_a_burst() {
        let mut w = World::new();
        let who = w.stranger();
        let start = w.now_ms - HOUR;
        for i in 0..20u64 {
            w.said_at(who, &format!("message {i}"), start + i * 100, 0);
        }
        let policy = rules_policy(|r| {
            r.rate = Some(crate::config::RateRule { enabled: true, per_secs: 60, messages: 5, gravity: Gravity::Minor })
        });
        let vs = w.verdicts(&policy);
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.iter().any(|f| f.rule_id == "rate"), "twenty messages in two seconds is a rate");
    }

    #[test]
    fn a_repetition_rule_convicts_the_same_line_over_and_over() {
        let mut w = World::new();
        let who = w.stranger();
        let start = w.now_ms - HOUR;
        for i in 0..10u64 {
            w.said_at(who, "buy my coin", start + i * 1000, 0);
        }
        let policy =
            rules_policy(|r| r.repetition = Some(crate::config::ToggleRule { enabled: true, times: 3, gravity: Gravity::Minor }));
        let vs = w.verdicts(&policy);
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.iter().any(|f| f.rule_id == "repetition"), "ten identical lines is repetition");
    }

    #[test]
    fn a_mass_tagging_rule_convicts_one_message_naming_a_crowd() {
        let mut w = World::new();
        let who = w.stranger();
        w.says_tagging(who, "everyone look at this", 30);
        let policy = rules_policy(|r| {
            r.mass_tagging = Some(crate::config::ToggleRule { enabled: true, times: 3, gravity: Gravity::Serious })
        });
        let vs = w.verdicts(&policy);
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.iter().any(|f| f.rule_id == "mass-tagging"), "thirty p-tags is a crowd");
    }

    /// A rule that is switched OFF must convict nobody.
    #[test]
    fn a_disabled_rule_convicts_nobody() {
        let mut w = World::new();
        let who = w.stranger();
        let start = w.now_ms - HOUR;
        for i in 0..20u64 {
            w.said_at(who, "buy my coin", start + i * 100, 0);
        }
        for policy in [
            rules_policy(|r| {
                r.rate = Some(crate::config::RateRule { enabled: false, per_secs: 60, messages: 5, gravity: Gravity::Minor });
                r.words = vec![WordRule { id: "x".into(), patterns: vec!["zzz".into()], gravity: Gravity::Note }];
            }),
            rules_policy(|r| {
                r.repetition = Some(crate::config::ToggleRule { enabled: false, times: 3, gravity: Gravity::Minor });
                r.words = vec![WordRule { id: "x".into(), patterns: vec!["zzz".into()], gravity: Gravity::Note }];
            }),
        ] {
            let vs = w.verdicts(&policy);
            let v = find(&vs, &who).expect("reported");
            assert!(v.findings.is_empty(), "a switched-off rule is off: {:?}", v.findings);
        }
    }

    /// Standing is earned from history, and the engine hands it to Sentinel as
    /// the shield the whole gate turns on.
    #[test]
    fn a_long_standing_regular_reads_as_trusted() {
        let mut w = World::new();
        let regular = w.regular(60 * 24 * HOUR, 500);
        for i in 0..10u64 {
            w.said_at(regular, &format!("morning {i}"), w.now_ms - (20 - i) * HOUR, 0);
        }
        w.says(regular, "badword");

        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Grave));
        let v = find(&vs, &regular).expect("reported");
        assert_eq!(v.shield, "trusted", "two months and five hundred messages is standing");
    }

    /// And a community that says so can still reach them.
    #[test]
    fn respect_trusted_decides_whether_a_regular_is_answerable() {
        let mut w = World::new();
        let regular = w.regular(60 * 24 * HOUR, 500);
        for i in 0..10u64 {
            w.said_at(regular, &format!("morning {i}"), w.now_ms - (20 - i) * HOUR, 0);
        }
        w.says(regular, "badword");

        // The rulebook is compiled from the SAME config the gate reads, because
        // shields gate before conviction: a community that has chosen to reach
        // its regulars has to say so in the rules or the engine spares them
        // upstream and the setting decides nothing.
        let rulebook = |cfg: &Config| {
            let mut c = cfg.clone();
            c.rules.words =
                vec![WordRule { id: "rude".into(), patterns: vec!["badword".into()], gravity: Gravity::Grave }];
            rules::compile(&c.for_community("")).expect("a rule is a rule")
        };

        let default = armed();
        let sparing = Pipeline::new(default.clone());
        assert_eq!(
            sparing.poll(&w, &rulebook(&default), &regular),
            None,
            "a regular is left to a person by default"
        );

        let mut cfg = armed();
        cfg.shields.respect_trusted = false;
        let reaching = Pipeline::new(cfg.clone());
        assert!(
            reaching.poll(&w, &rulebook(&cfg), &regular).is_some(),
            "unless the community says otherwise"
        );
    }

    /// Switching the shield off applies to every rule, not only the grave ones.
    /// Worth pinning: it is the widest thing that setting does, and the engine
    /// still has to accept the rulebook it produces.
    #[test]
    fn reaching_regulars_applies_to_every_rule_and_still_validates() {
        let mut w = World::new();
        let regular = w.regular(60 * 24 * HOUR, 500);
        for i in 0..10u64 {
            w.said_at(regular, &format!("morning {i}"), w.now_ms - (20 - i) * HOUR, 0);
        }
        w.says(regular, "badword");

        for gravity in [Gravity::Note, Gravity::Minor, Gravity::Serious, Gravity::Grave] {
            let mut cfg = armed();
            cfg.shields.respect_trusted = false;
            cfg.rules.words =
                vec![WordRule { id: "rude".into(), patterns: vec!["badword".into()], gravity }];
            Config::validate_for_test(&cfg)
                .unwrap_or_else(|e| panic!("{gravity:?} with respect_trusted off must still boot: {e}"));

            let policy = rules::compile(&cfg.for_community("")).expect("a rule is a rule");
            let vs = w.verdicts(&policy);
            let v = find(&vs, &regular).expect("reported");
            assert!(!v.findings.is_empty(), "{gravity:?} must reach a regular once the shield is off");
        }
    }

    /// The window is a real bound: what fell out of it convicts nobody.
    #[test]
    fn evidence_older_than_the_window_is_not_evidence() {
        let mut w = World::new();
        let who = w.stranger();
        // The default window is 168 hours.
        w.said_at(who, "badword", w.now_ms - 200 * HOUR, 0);

        let vs = w.verdicts(&word_policy("rude", &["badword"], Gravity::Grave));
        let v = find(&vs, &who).expect("reported");
        assert!(v.findings.is_empty(), "a week and a half ago is outside a one-week window");
    }

    /// A raid, end to end and offline: fresh accounts posting one line each,
    /// through the engine's own defaults, into Sentinel's containment decision.
    #[test]
    fn a_wave_of_fresh_accounts_saying_one_line_is_contained() {
        let mut w = World::new();
        let raiders: Vec<Who> = (0..8).map(|_| w.stranger()).collect();
        for r in &raiders {
            w.says(*r, "JOIN OUR CHANNEL NOW t.me/spam");
        }
        // A regular, saying something else entirely.
        let regular = w.regular(60 * 24 * HOUR, 400);
        for i in 0..5u64 {
            w.said_at(regular, &format!("morning all {i}"), w.now_ms - (10 - i) * HOUR, 0);
        }

        let vs = w.verdicts(&default_policy());
        assert!(vs.raid_detected(), "eight accounts posting one line is the raid shape");

        let mut cfg = armed();
        cfg.arm.raid = true;
        cfg.limits.halt_if_over_pct = 100;
        match crate::raid::select(&vs, &cfg.for_community(""), "npub1sentinel") {
            crate::raid::Containment::Contain { suspects, .. } => {
                assert_eq!(suspects.len(), raiders.len(), "the wave, and only the wave");
                assert!(
                    !suspects.contains(&regular.npub()),
                    "a regular caught in a raid sweep is the worst thing this can do"
                );
            }
            other => panic!("expected containment, got {other:?}"),
        }
    }

    /// The other half of the safety property: no cohort, no containment, no
    /// matter how busy the room is.
    #[test]
    fn ordinary_traffic_is_not_a_raid() {
        let mut w = World::new();
        // Genuinely different lines: the cohort matcher compares skeletons, and
        // "message 1" and "message 2" skeletonize to the same thing.
        let chatter = [
            "has anyone tried the new build yet",
            "the weather here is unbelievable today",
            "I finally finished that book about lighthouses",
            "does anyone know a good recipe for lentil soup",
            "my cat has learned to open the fridge",
            "thinking about learning to sail this summer",
            "the bus was forty minutes late again",
            "just saw the most enormous moth",
        ];
        for (i, line) in chatter.iter().enumerate() {
            let who = w.regular((10 + i as u64) * 24 * HOUR, 100 + i as u64 * 10);
            w.says(who, line);
        }
        let vs = w.verdicts(&default_policy());
        assert!(!vs.raid_detected(), "twenty people saying twenty things is a conversation");

        let mut cfg = armed();
        cfg.arm.raid = true;
        assert_eq!(
            crate::raid::select(&vs, &cfg.for_community(""), "npub1sentinel"),
            crate::raid::Containment::Quiet
        );
    }

    /// Containment is inference, so it stays rehearsed until an operator arms
    /// it in writing — the one switch that is not the ladder's.
    #[test]
    fn a_raid_is_only_rehearsed_until_arm_raid_is_set() {
        let mut w = World::new();
        for _ in 0..8 {
            let r = w.stranger();
            w.says(r, "JOIN OUR CHANNEL NOW t.me/spam");
        }
        let vs = w.verdicts(&default_policy());

        let mut cfg = armed();
        cfg.limits.halt_if_over_pct = 100;
        assert!(!cfg.arm.raid, "the ladder's switches say nothing about containment");
        assert!(matches!(
            crate::raid::select(&vs, &cfg.for_community(""), "npub1sentinel"),
            crate::raid::Containment::WouldContain { .. }
        ));
    }

    /// And a raid cohort is inference, so it must never reach the ladder.
    #[test]
    fn a_raid_cohort_earns_no_strikes() {
        let mut w = World::new();
        let raiders: Vec<Who> = (0..8).map(|_| w.stranger()).collect();
        for r in &raiders {
            w.says(*r, "JOIN OUR CHANNEL NOW t.me/spam");
        }
        let vs = w.verdicts(&default_policy());
        let cfg = armed();
        let p = Pipeline::new(cfg.clone());

        for r in &raiders {
            let v = find(&vs, r).expect("reported");
            assert!(!v.findings.is_empty(), "the engine did convict them");
            assert!(
                crate::review::charges(v, &cfg.for_community("")).is_empty(),
                "but on inference, which the ladder may not act on"
            );
            assert_eq!(p.answer(v, w.now_ms), None);
        }
    }

    /// A tiny deterministic generator. `Math::random` has no place in a test
    /// that has to fail the same way twice.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // xorshift64*, chosen for being four lines and reproducible.
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn upto(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Thousands of arbitrary histories, checked against the invariants that
    /// must hold whatever happened: never more than one rung per answer, never
    /// above what the total has earned, never anything the community cannot
    /// deliver, and never twice for the same evidence.
    #[test]
    fn the_ladder_holds_its_invariants_over_arbitrary_histories() {
        let cfg = armed();
        let p = cfg.for_community("");
        let hl = p.ladder.decay_half_life_hours;
        let hour = 3_600_000u64;

        for seed in 1..=400u64 {
            let mut rng = Rng(seed);
            let store = crate::store::tests::mem();
            let powers = crate::policy::Powers {
                hide: rng.next() % 2 == 0,
                kick: rng.next() % 2 == 0,
                ban: rng.next() % 2 == 0,
            };
            let mut strikes: Vec<crate::ladder::Strike> = Vec::new();
            let mut now = 1_000_000u64;
            let mut offenses = 0usize;
            let mut delivered = 0usize;

            for _ in 0..40 {
                now += rng.upto(hl * hour * 3) + 1;
                // Sometimes a new offense, sometimes just another poll over the
                // same evidence — which is what every poll actually is.
                if rng.upto(3) > 0 {
                    let worth = [1u32, 2, 4, 12][rng.upto(4) as usize];
                    strikes.push(crate::ladder::Strike { worth, at_ms: now });
                    offenses += 1;
                }
                let rung = crate::act::select_rung(&p, |r| powers.can_deliver(r), &store, "c", "npub1a", &strikes, now)
                    .unwrap();
                let Some(rung) = rung else { continue };

                assert!(powers.can_deliver(rung), "seed {seed}: proposed {rung:?} without the permission for it");

                let total = crate::ladder::total(&strikes, now, hl);
                let reached = crate::ladder::decide(&p.ladder, total).expect("a rung implies a step was reached");
                assert!(
                    rung.rank() <= reached.rank(),
                    "seed {seed}: answered {rung:?} for a total of {total}, which has only reached {reached:?}"
                );

                delivered += 1;
                assert!(
                    delivered <= offenses,
                    "seed {seed}: {delivered} answers for {offenses} offenses — the ladder is climbing on the clock"
                );

                store.log_action("c", "npub1a", rung.name(), now, "").unwrap();
            }
        }
    }

    /// The same, from the other side: nothing may ever answer for a member the
    /// community has vouched for, whatever the ledger says.
    #[test]
    fn a_shielded_member_is_never_answered_however_the_history_runs() {
        let cfg = armed();
        let p = cfg.for_community("");
        for seed in 1..=200u64 {
            let mut rng = Rng(seed);
            let shield = ["protected", "trusted", "unknown", "absent"][rng.upto(4) as usize];
            let facts = crate::adjudicate::Facts {
                shield,
                acted_this_pass: rng.upto(50) as usize,
                acted_this_hour: rng.upto(200) as usize,
                subjects_this_hour: rng.upto(50) as usize,
                roster: rng.upto(500) as usize,
                is_me: false,
            };
            let powers = crate::policy::Powers { hide: true, kick: true, ban: true };
            for rung in [
                crate::config::Response::Warn,
                crate::config::Response::DeleteAndWarn,
                crate::config::Response::Kick,
                crate::config::Response::Ban,
            ] {
                assert!(
                    matches!(
                        crate::adjudicate::adjudicate(&p, powers, &facts, rung),
                        crate::adjudicate::Sentence::Spare { .. }
                    ),
                    "seed {seed}: {shield} was not spared for {rung:?}"
                );
            }
        }
    }

    /// The citation-less skip must not disable an operator rule. Every rule
    /// Sentinel can compile has to reach the ledger, checked against the real
    /// engine rather than assumed.
    #[test]
    fn every_rule_an_operator_can_configure_reaches_the_ledger() {
        let cfg_of = |f: &dyn Fn(&mut crate::config::Rules)| {
            let mut cfg = armed();
            f(&mut cfg.rules);
            cfg
        };

        let cases: Vec<(&str, Box<dyn Fn(&mut crate::config::Rules)>)> = vec![
            (
                "words",
                Box::new(|r: &mut crate::config::Rules| {
                    r.words = vec![WordRule {
                        id: "words".into(),
                        patterns: vec!["badword".into()],
                        gravity: Gravity::Serious,
                    }]
                }),
            ),
            (
                "links",
                Box::new(|r: &mut crate::config::Rules| {
                    r.links = vec![LinkRule {
                        id: "links".into(),
                        domains: vec!["evil.example".into()],
                        gravity: Gravity::Serious,
                    }]
                }),
            ),
            (
                "rate",
                Box::new(|r: &mut crate::config::Rules| {
                    r.rate = Some(crate::config::RateRule { enabled: true, per_secs: 60, messages: 5, gravity: Gravity::Minor })
                }),
            ),
            (
                "repetition",
                Box::new(|r: &mut crate::config::Rules| {
                    r.repetition = Some(crate::config::ToggleRule { enabled: true, times: 3, gravity: Gravity::Minor })
                }),
            ),
            (
                "mass-tagging",
                Box::new(|r: &mut crate::config::Rules| {
                    r.mass_tagging = Some(crate::config::ToggleRule { enabled: true, times: 3, gravity: Gravity::Serious })
                }),
            ),
        ];

        for (name, build) in cases {
            let cfg = cfg_of(&*build);
            let policy = rules::compile(&cfg.for_community("")).expect("a rule is a rule");

            let mut w = World::new();
            let who = w.stranger();
            let start = w.now_ms - HOUR;
            // Traffic that trips all five: a listed word, a listed domain, a
            // burst, the same line repeatedly, and a message naming a crowd.
            for i in 0..20u64 {
                w.said_at(who, "badword at https://evil.example/x", start + i * 100, 0);
            }
            w.says_tagging(who, "badword everyone https://evil.example/x", 30);

            let vs = w.verdicts(&policy);
            let v = find(&vs, &who).unwrap_or_else(|| panic!("{name}: nobody reported"));
            assert!(!v.findings.is_empty(), "{name}: the engine convicted nobody");
            assert!(
                !crate::review::charges(v, &cfg.for_community("")).is_empty(),
                "{name}: convicted, and then charged nothing — the rule is decoration"
            );
        }
    }
}

