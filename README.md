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
decides, records and prints without acting.

Tested against the real engine offline — 217 tests, about as many lines of test as of code.
`src/harness.rs` builds a community in memory, runs the actual policy engine over it, and
converts the result through the same code path the live bot uses, so "three offenses reach a
kick" is checked from the words to the rung with no network involved. A raid is driven the
same way, through the engine's own defaults. What is not covered is the act itself and the
relay round-trip.

Not yet run against a real raid. Nothing here is field-tested.

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
   week apart do not — measured from when Sentinel SAW them. A verdict carries no timestamp
   for its evidence, so a backfill after downtime charges an old pair as a fresh one.
4. The running total meets the **ladder**, and Sentinel answers with the next rung up from
   whatever that member last received: warn, delete and warn, kick, ban. It climbs rather
   than jumping, so a member who accrued enough for a ban in one burst still gets warned
   first.

   It climbs per **offense**, not per pass. An answer records the total it answered, and the
   next rung is owed only once the total rises above it — otherwise a verdict re-reporting a
   standing conviction every poll would walk one message up the whole ladder in minutes. That
   recorded total is aged by the same halving that forgives strikes, so a kick from March
   stops making a light offense in October answerable only by a ban.

   A rung this community grants no permission for is skipped rather than blocking the ones
   above it, and an unarmed one is rehearsed and recorded, so the ladder goes on climbing
   past it. Arming `kick` while `warn` is off is a real configuration: the warning is
   rehearsed and the kick is delivered.

Two things have to be true before a conviction earns a strike, and they answer different
questions. Its **basis** must be deterministic: windowed inference is reported to the mod
channel for a person to answer, never sentenced — except raid containment, which an operator
arms explicitly with `[arm] raid`. And it must **cite** something. The engine's raid
aggravators describe a person rather than an act — an account under a day old, one that has
posted twice — and cite nothing; a cohort is what arms them. Without that second condition,
being new was an offense for everyone caught in a raid detection, with the raid switch off.

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
never contained), the blast-radius ceiling applies (below), and bans go out via `ban_many` in
batches — each individual ban rotates the community's keys, and forty rotations strand
everyone.

## The blast radius

`[limits] halt_if_over_pct` and `halt_floor` cap how many **distinct people** Sentinel may
answer for in one community in an hour. Past that it stops and asks a person.

This is not a rate limit, and it is not per member: every member has their own strikes, their
own decaying total and their own rung, and none of that is shared. It is the blast radius — a
misconfigured rule, an engine bug or a bad raid call must not be able to walk the whole
memberlist while nobody is watching.

The percentage scales with the community and the floor keeps a small one working; whichever is
larger wins, and neither can exceed the roster. A percentage alone was the wrong shape: 10% of
four members floors to one, so the second offender in an hour deadlocked the bot — and a halt
also defers raid containment and skips the debt loop for that pass. The member currently being
answered is excluded from the count, so someone already inside the bound still climbs.

## The media lane

Optional, off by default. When `[vision] enabled` is set, Sentinel decrypts attachments as
they arrive, asks a vision model to score them against labels you named, and feeds anything
over its threshold into the same strike ladder as everything else.

Each label carries the operator's own `describe` sentence, sent to the model with the name —
a bare label is the model's guess at what a community means by "spam", and a sentence is the
operator's answer. The model returns a score per label **and** one sentence describing what the
media actually shows, which is stored on the strike record: a moderator reviewing a decision
months later reads a line of text instead of reopening the worst thing somebody posted.

The answer shape is pinned by a JSON schema where the endpoint supports one, and checked by the
parser regardless. A reply that is prose, fenced, truncated or missing a label is sent back with
the fault named, up to `max_attempts`. That bound is deliberate: a model that never complies
would hold the blob slot and spend the budget forever, and unjudged — which escalates to a
person — is the safe end of that. Images and video both, by
whatever `[vision] mimes` lists.

Video is not sent to the model whole, because no vision endpoint reads an mp4. ffmpeg samples
frames evenly across the **whole** clip and tiles them into one contact sheet, judged in a
single call — so the thing worth catching is not hidden by being at 4:12 rather than 0:00.
Animated GIF and WebP take the same path for the same reason. The grid shrinks to fit a clip
with fewer frames than cells, since a blank tile costs pixels and asks the model to read a
hole. Set the grid under `[vision.video]`.

This is the one place Sentinel points a parser it did not write at attacker-supplied bytes, so
ffmpeg runs as a **child process** under a wall clock: a decoder bug kills a child rather than
the bot. Without ffmpeg on PATH, clips reach a person unjudged and still images are unaffected.

llama.cpp's `llama-server` speaks the OpenAI-compatible shape out of the box, so local is the
default and remote is the same block with a different `base_url`. That switch is deliberate:
an attachment is end-to-end encrypted right up until Sentinel decrypts it and posts it to
somebody else's server, so `allow_remote` has to be set on purpose or startup refuses.

Three rules this lane keeps:

- **A model's verdict is Sentinel's opinion, not the engine's.** It never reaches `proven`,
  never enters the combinator, and never appears in another client's report — but within
  Sentinel it is the answer. If the model says it breaks a rule, it breaks a rule.
- **Unknown is not clean.** A timeout, a refusal or a malformed answer routes to a human. An
  unreachable model is a reason to ask, never a reason to let everything through.
- **The bytes are never kept.** Classification happens in memory; only the content hash and
  the verdict are stored, so forty accounts posting one image cost a single call. The cache
  key carries the labels and thresholds it was asked about, so adding a label re-asks rather
  than serving an answer to a question nobody asked.
- **The sender's filename decides nothing.** It says whether something could be media at all;
  the bytes say what it is. Anything claiming to be an image or a video is fetched and
  answered for, and whatever the operator did not list goes to a person — a client renders by
  extension, so a type Sentinel skipped in silence would still be on screen.
- **One post is one sentence.** If the text screen already answered for a post, a flagged
  attachment on it is recorded but not answered again — so the hide waits for the rung that
  does the hiding. A post carrying only media is answered immediately.
- **One community's flood is its own.** The classifier budget is per community, and its
  single permit is held from before the fetch, so a wave in one room cannot spend the minute
  of another. That bounds each community to one blob in memory at a time — N watched
  communities is N of them, not one.

## Asking it things

Inside a community, from any client that renders slash commands:

- `/status` — what it is watching, and how much history it can actually see
- `/why <member>` — their strike record, decayed, and the next step
- `/pardon <member>` — clear it, and lift the ban. Moderators only; the community's own
  roles decide. Both halves, or it is not an undo: a member Sentinel removed would otherwise
  stay removed with a clean slate.

Every armed sentence is **announced before it is carried out**, when a mod channel is named.
The two want opposite sides of the act: an operator has to see what is about to happen, and
the ledger must hold only what did. A channel that was named and cannot be reached holds the
sentence — a bot removing people with no record of it is the incident the audit trail exists
to prevent. Name no channel and nothing is held; that is the operator's call, made once.

A pardon tombstones the strikes and clears the action history. Both halves matter: the strikes
must survive as tombstones because the engine re-reports the same convictions for as long as
the evidence sits in its window, and the history must go because a forgiven member who kept it
stays immune to every response below the one they already received.

Changing what is armed in `[arm]` wipes that community's slate, tombstones included. That
wipe is what lets one ledger hold both rehearsals and real actions: a rehearsal records
everything a real answer would, so the ladder climbs, the ceilings fill, and an operator
watches the run they are about to arm rather than meeting it for the first time when the
switch flips. Keeping two spaces instead would mean every read having to know which one it
was in, and getting that wrong is silent.

## Proven vs unproven

The axis everything turns on, and it is **not** a confidence level.

A raid cohort reads confidence 90 and proven 0. The engine is certain something is
happening and nobody else could replay it. *Proven* evidence is byte-checkable by any
client holding the same policy and history. *Unproven* evidence is a judgement about a
pattern, true only of the window it was measured over.

Engine inference does not sentence: a windowed heuristic is reported to the mod channel for a
person to answer. Sentinel's own lanes are a different matter. When the model says an image or
video breaks a rule, that is the answer — it earns a strike and climbs the ladder like any
other offense.

The two are told apart by a marker Sentinel stamps on its own findings, never by the absence
of the engine's. A field that goes missing upstream must not be able to promote inference into
something a ladder rung acts on.

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
