//! A confidential-computing transport for the vision lane.
//!
//! Same OpenAI-shaped body as [`super::openai`], carried differently: the
//! request is sealed with HPKE to a key the enclave proved it holds, so the
//! machine running the model cannot read the attachment and neither can the
//! proxy that bills for it.
//!
//! What is attested is the inference ROUTER, not the GPU. The router terminates
//! the encrypted channel, then forwards to a model enclave it verified itself.
//! The plaintext exists in measured, publicly audited code rather than in no
//! code at all, and that distinction belongs in the operator's head, so
//! `describe()` prints the measurement instead of the word "private".

use tinfoil::Client;

use crate::config::VisionCfg;

pub struct Tee {
    client: Client,
    /// Release and measurement of whatever answered, for the boot line.
    ground: String,
}

impl Tee {
    /// Connect and attest. Verification happens here rather than on first use:
    /// an operator learns their key or the enclave is wrong at boot, not when
    /// the first raid image needs judging.
    pub async fn connect(cfg: &VisionCfg) -> Result<Self, String> {
        let key = std::env::var(&cfg.api_key_env)
            .map_err(|_| format!("vision.api_key_env {} is unset", cfg.api_key_env))?;
        let mut client = Client::new_with_proxy(
            cfg.enclave_host.clone(),
            cfg.enclave_repo.clone(),
            key,
            cfg.enclave_proxy.clone(),
        )
        .await
        .map_err(|e| format!("enclave client: {e}"))?;
        let g = client.verify().await.map_err(|e| format!("enclave attestation failed: {e}"))?;
        // The two fingerprints agree whenever the running enclave IS the signed
        // release, which is the ordinary case; printing both then says the same
        // thing twice. A divergence is the whole point of measuring, so that is
        // when the second one is worth the room.
        let measured = if g.code_fingerprint == g.enclave_fingerprint {
            short(&g.code_fingerprint)
        } else {
            format!("code {} != enclave {}", short(&g.code_fingerprint), short(&g.enclave_fingerprint))
        };
        let ground = format!(
            "{} {} — {measured}",
            g.config_repo,
            g.release_tag.as_deref().unwrap_or("untagged"),
        );
        Ok(Tee { client, ground })
    }

    pub fn describe(&self) -> &str {
        &self.ground
    }

    pub async fn post(&self, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        self.client
            .chat_relaxed()
            .create(body.clone())
            .await
            .map(|r| r.into_raw())
            .map_err(|e| e.to_string())
    }
}

fn short(digest: &str) -> String {
    digest.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Gravity, VisionLabel, VisionProvider};
    use crate::vision::{openai::OpenAiVision, Shown, Verdict, Vision};

    /// One real classification against the live enclave. Ignored by default: it
    /// needs a key, costs money, and a network failure is not a code failure.
    ///
    ///   PPQ_API_KEY=… TEE_PROBE_IMAGE=/path/to.png \
    ///     cargo test tee::tests::a_real_image -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn a_real_image_round_trips_through_the_sealed_wire() {
        let path = std::env::var("TEE_PROBE_IMAGE").expect("TEE_PROBE_IMAGE");
        let bytes = std::fs::read(&path).expect("readable image");
        let mime = vector_sdk::vector_core::crypto::mime_from_magic_bytes(&bytes);

        let cfg = VisionCfg {
            enabled: true,
            provider: VisionProvider::Tee,
            model: std::env::var("TEE_PROBE_MODEL").unwrap_or_else(|_| "gemma4-31b".into()),
            api_key_env: "PPQ_API_KEY".into(),
            timeout_secs: 180,
            labels: vec![VisionLabel {
                name: "sexual_content".into(),
                title: "NSFW".into(),
                describe: "Nudity or sexual content in any art style.".into(),
                threshold: 0.8,
                gravity: Gravity::Grave,
            }],
            ..VisionCfg::default()
        };

        let eyes = OpenAiVision::new(cfg).await.expect("attest and connect");
        println!("endpoint: {}", eyes.endpoint());

        let t = std::time::Instant::now();
        let verdict = eyes.classify(&bytes, Shown::Still { mime }).await;
        println!("{}ms — {verdict:?}", t.elapsed().as_millis());

        // The wire is what is under test: an answer of any shape proves the data
        // URI reached a model and a scored reply came back. WHAT it scored is
        // the model's business.
        assert!(
            !matches!(verdict, Verdict::Unknown(_)),
            "the sealed wire did not produce an answer: {verdict:?}"
        );
    }
}
