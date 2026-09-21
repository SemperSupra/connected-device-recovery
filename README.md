# Connected Device Recovery

Reusable tooling, schemas, sanitized fixtures, recovered specifications, and qualification outputs for understanding and interoperating with connected-device ecosystems.

This is the public/build/deploy counterpart to the private development effort. Proprietary artifacts, credentials, account/session material, private captures, and unsanitized evidence do not belong here.

## Relationship to Android Artifact Recovery

Connected Device Recovery may use `SemperSupra/android-artifact-recovery` for APK/DEX/native extraction, artifact normalization, version differencing, and Android instrumentation. AAR remains an independent capability provider rather than the owner of device-specific investigations.

## Method

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

The project favors bounded experiments, provenance, negative results, and upstream contribution over independent reimplementation.
