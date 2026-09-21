# Recovery Method

Connected Device Recovery is organized around claims and deltas rather than applications or protocol silos.

```
external knowledge
      ↓
assertion
      ↓
controlled reproduction
      ↓
qualified known-space
      ↓
behavioral delta
      ↓
relevant unknown
      ↓
smallest discriminating experiment
      ↓
new qualified knowledge
      ↓
fixture / specification / upstream contribution
```

## Principles

1. **Known work becomes an oracle.** Reuse existing implementations and documentation with provenance.
2. **Unknowns drive work.** Do not reverse engineer code merely because it exists.
3. **One change per experiment where practical.** Differential experiments should isolate variables.
4. **Negative results count.** A hypothesis ruled out is durable knowledge.
5. **Physical hardware is an arbiter, not the default test jig.** Prefer static artifacts and simulated/virtual surfaces when they answer the question.
6. **Just-in-time emulation.** Implement only the device behavior required by the next experiment.
7. **Public/private membrane.** Publish reusable, sanitized outcomes; retain sensitive/raw evidence privately.
8. **Qualification is separate from discovery.** A discovery is not qualified until independently reproducible.
