# Sentinel

A moderation bot for [Vector](https://vectorapp.io) communities.

**Two judges, one enforcer.** vector-core's policy engine judges text, a vision model
judges media, and Sentinel alone decides the sentence: warn, delete, kick, ban, or
contain a raid.

The split matters. The engine **convicts and never sentences** — it reports "this member
matched this rule, here is the proof" and stops. Sentinel is the consumer that decides
what any of that is worth.

## Status

Early, but complete: live content screening, a periodic sweep, raid containment, and an
optional media lane, all feeding one strike ladder. **Nothing is armed by default**, so it
rehearses and prints instead of acting.

Not yet run against a real raid. Every safety property below is unit-tested and none is
field-tested.

## Running

```sh
cp sentinel.example.toml sentinel.toml
SENTINEL_NSEC=nsec1… cargo run
```

A missing config is the defaults: no custom rules, nothing armed. Invite Sentinel to a
community from the Vector app; it builds `.public()`, so anyone can. It needs no permissions
to *watch* — evaluation is local computation over history it has synced — but it needs KICK,
BAN or MANAGE_MESSAGES to carry a sentence out.

## Two clocks

Sentinel judges on two timescales, because the rules themselves come in two kinds.

**Immediate — the moment a message lands.** Word filters, link blocking, regex and mention
spam settle from the message alone, so they run on arrival and answer in milliseconds. NSFW
media is the same: attachments are classified as they arrive. A word filter that answers on
the next tick is not a word filter.

**Periodic — every `poll_secs` (90s floor).** Rate limits, repetition, raid cohorts and join
bursts are statements about a *window*. There is nothing for them to measure in one message,
so they belong to the sweep. They are absent from the live path rather than wrongly clean.

**Tripped — the moment a wave starts.** Waiting up to 90 seconds to notice a raid is not
moderation, so the sweep is a floor, not the only clock. Sentinel watches the live stream for
the one thing a raid cannot hide: many *distinct* accounts speaking or joining at once. When
`[raid] tripwire_accounts` of them appear inside `tripwire_secs`, it drops the memoised
verdict and evaluates immediately.

The tripwire counts **strangers**, not accounts. Every sweep hands it the engine's own list of
vouched-for members, and those cost nothing to ignore — ten regulars mid-conversation are the
least raid-shaped thing there is, and counting them would fire a full corpus read every minute
for as long as the room stayed lively.

It decides **when to ask, never who is guilty**. The engine still reaches every verdict. Keeping those apart is what stops a
second, sloppier detector growing beside the real one. A cooldown bounds it, because an
evaluation is a full corpus read and a sustained wave would otherwise ask for one per
message.

Both paths run the same engine over the same policies, so a verdict reached live is the
verdict the sweep would reach later over the same text, and both feed one strike ladder —
a member escalates once, not twice.

## How it decides

1. The engine convicts, reporting which rule matched, how grave its author called it, and
   which messages it cited.
2. Sentinel translates gravity into **strikes**, recorded once per conviction. Verdicts
   re-report every standing conviction on every poll, so the conviction id is what separates
   an offense from an echo of one.
3. Strikes **decay by halves**. Two serious offenses in a week reach a kick; the same pair a
   week apart do not.
4. The running total meets the **ladder** and a response comes out: warn, delete and warn,
   kick, ban.

Only *proven* convictions earn strikes, on either clock. Inference is reported and never
sentenced — except where an operator arms it explicitly (`[arm] raid`, `[arm] vision`), which
is a decision made in writing rather than inherited from a switch meant for something else.

## One decision, four lanes

Every sentence — the sweep's ladder, the live text screen, the media lane, raid containment —
is decided by a single pure function, `adjudicate`. It takes the facts and returns a verdict:
spare, already answered, held, halt, powerless, or carry it out.

Raid containment answers to its own gates as well as this one — a raid is one event rather
than N sentences, so it applies standing, powers and the roster ceiling through
`raid::select` and per-member claims, and it is skipped entirely in a pass where the ladder
already halted.

The lanes do not decide anything. They gather facts, ask, and obey. That is what makes the
guards testable without a network, and what stops the next lane reaching an action without
passing them — a guard living inside the function that *acts* is a guard each new caller can
route around, which is exactly what happened twice before this shape.

The order is fixed: standing, then powers, then dedup, then ceilings.

## Per-community, all the way down

Sentinel is invited into communities it does not own, whose standards differ and whose
operators trust it with different amounts. Nothing leaks between them: separate rulebooks,
ladders, arming, tripwires, strike history and roster ceilings.

And separate **powers**. Being a member is not being a moderator. A community can grant
`MANAGE_MESSAGES` and withhold `BAN`, so Sentinel reads what each one actually permits and
reports a sentence it cannot carry out rather than attempting it and having every reader drop
the publish. The boot line says what it can do where.

## Raids skip the ladder

A raid is a single event, not forty members each earning strikes. Escalating through warnings
while a hundred fresh accounts post the same line is the wrong shape entirely, so a detected
raid elevates straight to whatever `[raid] response` you chose: report, kick, or ban.

This is the one place Sentinel acts on **inference**. A cohort reads high confidence and zero
proven: nobody can replay it, and the engine's rule is that inference may not sentence. Arming
`[arm] raid` is you overriding that, deliberately, for this case. It is false by default.

Even armed, three things still hold: shields survive (a trusted regular caught in a wave is
never contained), a pass that would touch more than `halt_if_over_pct` of the roster stops and
asks for a person, and bans go out via `ban_many` in batches — each individual ban rotates the
community's keys, and forty rotations strand everyone.

## The media lane

Optional, off by default. When `[vision] enabled` is set, Sentinel decrypts attachments as
they arrive, asks a vision model to score them against labels you named, and feeds anything
over its threshold into the same strike ladder as everything else.

llama.cpp's `llama-server` speaks the OpenAI-compatible shape out of the box, so local is the
default and remote is the same block with a different `base_url`. That switch is deliberate:
an attachment is end-to-end encrypted right up until Sentinel decrypts it and posts it to
somebody else's server, so `allow_remote` has to be set on purpose or startup refuses.

Three rules this lane keeps:

- **A model's verdict is Sentinel's opinion, not the engine's.** It never reaches `proven`,
  never enters the combinator, and never appears in another client's report.
- **Unknown is not clean.** A timeout, a refusal or a malformed answer routes to a human. An
  unreachable model is a reason to ask, never a reason to let everything through.
- **The bytes are never kept.** Classification happens in memory; only the content hash and
  the verdict are stored, so forty accounts posting one image cost a single call.

## Asking it things

Inside a community, from any client that renders slash commands:

- `/status` — what it is watching, and how much history it can actually see
- `/why <member>` — their strike record, decayed, and the next step
- `/pardon <member>` — clear it. Moderators only; the community's own roles decide.

A pardon clears the action history as well as the strikes: leaving the history behind meant a
forgiven member stayed immune to every response below the one they had already received.

## Proven vs unproven

The axis everything turns on, and it is **not** a confidence level.

A raid cohort reads confidence 90 and proven 0. The engine is certain something is
happening and nobody else could replay it. *Proven* evidence is byte-checkable by any
client holding the same policy and history. *Unproven* evidence is a judgement about a
pattern, true only of the window it was measured over.

Inference may not sentence. Who the second judge is — a person, a model, Sentinel's own
ruleset — is a choice, and Sentinel exists to make it deliberately.

## Coverage is not a detail

Policy evaluation is client-side, over history the evaluating device actually holds. A
phone with the app closed evaluates nothing; a moderator who joined yesterday judges a
three-year-old community on a few hundred messages.

Sentinel is the always-on device that fixes this. Its verdicts cover exactly what Sentinel
has synced, and it says so rather than implying more.

## Building against the Vector working tree

`Cargo.toml` carries an **active** `[patch.crates-io]` block pointing at a local Vector
checkout at `../Vector`. It is currently required: the verdict fields Sentinel reads
(`band`, `shield`, `findings`, `coverage`) are not in a published release yet. Comment it
out once `vector-core 0.9` and `vector_sdk 0.10` are on crates.io.

## License

MIT
