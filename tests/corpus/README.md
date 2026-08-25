# Adversarial corpus

All corpus inputs are checked in as ASCII hexadecimal so diffs remain
reviewable and platform-independent. Tests decode `*.hex` with
`bytes.fromhex()`.

- `audit/` contains permanent reproductions from the correctness audit.
- `malformed/` contains inputs that both the strict UHC path and the relevant
  native decoder/container must reject.

Add every minimized future failure here before fixing it. Do not overwrite an
existing seed; add a new descriptively named file and a focused regression.
