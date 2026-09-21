# Connected Device Recovery — Public Context

## Purpose

This repository contains reusable, sanitized outputs from connected-device recovery work: schemas, harness components, fixtures, recovered specifications, qualification results, and documentation.

## Boundaries

- Device/ecosystem investigations are owned by Connected Device Recovery.
- Android Artifact Recovery (AAR) is a capability provider, not a parent project.
- Proprietary binaries, credentials, tokens, private captures, account/session identifiers, and unsanitized evidence stay out of this repository.
- External implementations are evidence sources and executable oracles; they are not automatically ground truth.

## Claim states

- `external`: asserted or implemented elsewhere.
- `observed`: directly measured by the recovery effort.
- `qualified`: independently reproducible with durable evidence/fixture.

## Working rule

Every recovery task names an unresolved behavioral question and the smallest experiment that can discriminate among plausible explanations.

The project prefers upstream contributions and interoperable specifications over permanent forks or unnecessary reimplementation.
