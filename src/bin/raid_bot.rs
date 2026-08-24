//! A single throwaway raider, for stress-testing Sentinel's anti-raid lane.
//!
//! One PROCESS is one identity: a fresh minted nsec in its own `data_dir`, so
//! the SDK's per-account globals never collide (the launcher runs N of these in
//! parallel, which is what a real raid looks like — N independent clients, not
//! one process wearing N hats). It joins a public link, posts one identical
//! line so the cohort rule clusters them, and exits.
//!
//! Usage: raid_bot <invite_url> <index> <spam_text>

use vector_sdk::VectorBot;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (url, idx, spam) = match args.as_slice() {
        [_, url, idx, spam] => (url.clone(), idx.clone(), spam.clone()),
        _ => {
            eprintln!("usage: raid_bot <invite_url> <index> <spam_text>");
            std::process::exit(2);
        }
    };
    let tag = format!("raider-{idx}");

    // Fresh identity, isolated store. No nsec → build() mints one.
    let dir = std::env::temp_dir().join("vector-raid").join(&idx);
    let _ = std::fs::remove_dir_all(&dir); // a clean identity every run
    let bot = match VectorBot::builder().data_dir(&dir).public().build().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[{tag}] build failed: {e}");
            std::process::exit(1);
        }
    };
    println!("[{tag}] up as {}", bot.npub());

    // Join the community from the public link.
    let summary = match bot.core().join_community(&url).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{tag}] join failed: {e}");
            std::process::exit(1);
        }
    };
    // Post to the first PUBLIC channel — a public link only vends those, and
    // the general channel is where a raid would land.
    let channel_id = summary["channels"]
        .as_array()
        .and_then(|chs| {
            chs.iter()
                .find(|c| c["private"].as_bool() != Some(true))
                .or_else(|| chs.first())
        })
        .and_then(|c| c["channel_id"].as_str())
        .map(|s| s.to_string());
    let Some(channel_id) = channel_id else {
        eprintln!("[{tag}] joined but found no channel to post to: {summary}");
        std::process::exit(1);
    };
    println!("[{tag}] joined, posting to {}", &channel_id[..8.min(channel_id.len())]);

    // The identical line is the point: same skeleton across raiders → one cohort
    // cluster. Two posts each keeps every raider under the cohort's quiet_max=2
    // thinness bar (a loud author reads as a regular, not a thin cohort member).
    for n in 1..=2 {
        match bot.channel(&channel_id).send(&spam).await {
            Ok(_) => println!("[{tag}] posted {n}/2"),
            Err(e) => eprintln!("[{tag}] send {n} failed: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }

    // Let the publishes settle on the relays before the process (and its client)
    // tears down — a raider that exits mid-publish never lands its evidence.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    println!("[{tag}] done");
}
