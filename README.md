# Sentinel

A moderation bot for [Vector](https://vectorapp.io) communities.

**Two judges, one enforcer.** vector-core's policy engine judges text, a vision model
judges media, and Sentinel alone decides the sentence: warn, delete, kick, ban, or
contain a raid.

The split matters. The engine **convicts and never sentences** — it reports "this member
matched this rule, here is the proof" and stops. Sentinel is the consumer that decides
what any of that is worth.

## Status

Early. The text lane works end to end: rules compile from config, convictions become
strikes, strikes decay, and the ladder decides a response. **Nothing is armed by default**,
so it rehearses and prints instead of acting. The media lane and raid containment are not
written yet.

## Running

```sh
cp sentinel.example.toml sentinel.toml
SENTINEL_NSEC=nsec1… cargo run
```

A missing config is the defaults: no custom rules, nothing armed. Invite Sentinel to a
community from the Vector app; it builds `.public()`, so anyone can. It needs no permissions
to *watch* — evaluation is local computation over history it has synced — but it needs KICK,
BAN or MANAGE_MESSAGES to carry a sentence out.

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

Only *proven* convictions earn strikes. Inference is reported and never sentenced.

## Asking it things

Inside a community, from any client that renders slash commands:

- `/status` — what it is watching, and how much history it can actually see
- `/why <member>` — their strike record, decayed, and the next step
- `/pardon <member>` — clear it. Moderators only; the community's own roles decide.

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

`Cargo.toml` carries a commented `[patch.crates-io]` block. Uncomment it to build against
a local Vector checkout at `../Vector` while developing SDK or core changes underneath
Sentinel. It is currently **required**: the verdict fields Sentinel reads (`band`,
`shield`, `findings`) are not in a published release yet.

## License

MIT
