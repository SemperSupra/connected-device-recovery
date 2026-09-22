# Campaign contracts

Connected Device Recovery (CDR) owns campaign questions, evidence interpretation,
unknowns, safety boundaries, and conclusions. Analysis systems such as Android
Artifact Recovery (AAR), local harnesses, emulators, and Agent Dispatch remain
capability providers.

The campaign contract intentionally stays small:

- `campaign.yaml` identifies the stable campaign, targets, providers, oracle
  exposure, authority, safety boundaries, consumers, and historical evidence.
- root-level worksets identify executable work and dependencies for one campaign.
- external implementations are evidence/oracles, not automatic truth.
- `evaluator_only` oracles remain unavailable to a recovery actor until the
  recovery result is sealed when a blind qualification is required.
- registration does not authorize execution; campaign status and work-item state
  remain separate.
- campaign-specific evidence is not copied out of its authoritative repository
  merely to change ownership.

The generic validator checks schema conformance, campaign references, duplicate
work-item IDs, and `blocked_by` references. It deliberately does not implement a
scheduler or execution engine.
