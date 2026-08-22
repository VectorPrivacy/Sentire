//! Sentinel: a moderation bot for Vector communities.
//!
//! Two judges, one enforcer. vector-core's policy engine judges text, a vision
//! model judges media, and Sentinel alone decides the sentence.
//!
//! This slice is the text lane, report-only. It removes nobody, and the code to
//! remove anyone does not exist yet.
//!
//! ```sh
//! SENTINEL_NSEC=nsec1… cargo run
//! ```

use std::time::Duration;

use vector_sdk::policy::{Verdict, Verdicts};
use vector_sdk::{Community, VectorBot};

/// The report is memoised for 90s inside vector-core, so anything faster than
/// this re-parses bytes it has already seen.
const POLL: Duration = Duration::from_secs(90);

#[tokio::main]
async fn main() -> vector_sdk::Result<()> {
    let nsec = std::env::var("SENTINEL_NSEC").expect("set SENTINEL_NSEC to Sentinel's nsec");

    let bot = VectorBot::builder().nsec(nsec).public().build().await?;
    println!("Sentinel online as {}", bot.npub());
    println!("REPORT ONLY — this build has no code that removes anyone.\n");

    let communities = bot.communities().await;
    if communities.is_empty() {
        println!("Not a member of any community yet. Invite Sentinel from the Vector app.");
    }
    for c in &communities {
        println!("watching {}", c.id());
    }

    loop {
        for c in &communities {
            if let Err(e) = sweep(c).await {
                eprintln!("{}: {e}", &c.id()[..12]);
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// One pass over a community's standing.
async fn sweep(community: &Community) -> vector_sdk::Result<()> {
    let verdicts = community.verdicts().await?;
    let id = &community.id()[..12];

    // Proven and unproven are the axis, not a confidence level: a raid cohort
    // reads high confidence and zero proven. Both are printed, and the
    // distinction is what a later build will act on differently.
    let mut found = 0;
    for v in verdicts.proven() {
        report(id, "PROVEN  ", v);
        found += 1;
    }
    for v in verdicts.unproven() {
        report(id, "INFERRED", v);
        found += 1;
    }
    if verdicts.raid_detected() {
        println!("[{id}] RAID SUSPECTED");
    }
    heartbeat(id, &verdicts, found);
    Ok(())
}

/// What the sweep looked at, whether or not it found anything.
///
/// A quiet community and a broken bot print the same thing — nothing — and that
/// is exactly how a moderation tool stays broken for months. Every pass says
/// what it read and how many people it weighed, so silence becomes a result
/// rather than an absence of one.
fn heartbeat(community: &str, verdicts: &Verdicts, found: usize) {
    let cov = verdicts.coverage();
    let mut shields = (0, 0, 0);
    for v in verdicts.all() {
        match v.shield.as_str() {
            "protected" => shields.0 += 1,
            "trusted" => shields.1 += 1,
            _ => shields.2 += 1,
        }
    }
    let history = if cov.is_empty() {
        // Not a clean community. An unread one.
        "NO HISTORY — nothing was judged".to_string()
    } else {
        format!(
            "{} msgs over {}h across {} channel(s){}{}",
            cov.corpus,
            cov.span_hours(),
            cov.channels,
            if cov.is_saturated() { ", WINDOW FULL (older history unread)" } else { "" },
            if cov.complete { "" } else { ", partial" },
        )
    };
    println!(
        "[{community}] swept {} member(s) — {} protected, {} trusted, {} plain — {found} convicted — {history}",
        verdicts.all().count(),
        shields.0,
        shields.1,
        shields.2,
    );
}

fn report(community: &str, kind: &str, v: &Verdict) {
    println!(
        "[{community}] {kind} {} — {} (confidence {}, proven {}, {}, shield {})",
        &v.npub[..12.min(v.npub.len())],
        v.why(),
        v.confidence,
        v.proven,
        v.band,
        v.shield
    );
    for f in &v.findings {
        println!(
            "           · {} [{}] {}×  weight {}{}{}",
            f.rule_id,
            f.severity,
            f.hits,
            f.weight,
            if f.detail.is_empty() { String::new() } else { format!("  matched {:?}", f.detail) },
            if f.messages.is_empty() {
                String::new()
            } else {
                format!("  cites {} message(s)", f.messages.len())
            },
        );
    }
}
