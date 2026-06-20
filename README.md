# SPTA — Scroll-Press Timing Authentication

**Behavioral password hash without text entry.**

A password authentication protocol where the user never types their password.
Words scroll on screen; the user presses a single button when the current word
contains the letter they are counting in their phrase. No text is typed, no
hash is transmitted, no credential is stored in reversible form.

## The Problem with Password Authentication

Traditional password systems store . When the database
leaks, offline brute-force recovers passwords. When the user logs in, the
password travels over the wire (TLS or not) and is visible to keyloggers and
phishing forms.

## What SPTA Does

| Classic Attack        | SPTA Response                                    |
|-----------------------|--------------------------------------------------|
| Keylogger             | Nothing to log — user presses one button         |
| Phishing form         | No text field exists to clone                    |
| Credential stuffing   | Timing is device+session specific, not replayable|
| Hash database breach  | Server stores timing profile, not password hash  |
| Shoulder surfing      | Observer sees words, not which letter is active  |

## Protocol

1. User enrolls a memorable phrase (e.g. ).
2. Device generates a word sequence using a session-seeded PRNG.
3. Words scroll one per ~1.2 seconds.
4. For each letter in the phrase, user presses SPACE when the displayed word
   **contains** that letter.
5. Server verifies: (a) pressed words contain the correct letters, (b) timing
   within each word's window matches enrolled baseline (z-score check).

### Key Properties

**Controlled letter frequency.** The word list is curated so every letter
A–Z appears in ~10–30% of displayed words. This equalizes expected wait time
across letters, eliminating the timing side-channel that reveals rare vs.
common letters (Q would otherwise cause a much longer pause than E).

**Session-keyed word sequence.** Each authentication session uses a fresh
PRNG seed. The same phrase produces a different word sequence every time.
Captured sessions cannot be replayed.

**Random press duplication.** The user may press multiple times for one
letter (on two consecutive matching words). The verifier accepts any number
of valid presses per letter position. This hides phrase length from observers
and adds partition ambiguity (~10 bits per session).

**Password-as-memory.** The phrase never exists in digital form. Recovery from
partial forgetting is possible: the words pressed serve as episodic memory
anchors — the word  reminds the user *why* they pressed at that
moment, reconstructing the forgotten letter without any server-side hint.

> **Prototype note:** This reference implementation stores the phrase in plaintext
> at  for simplicity. A production implementation should
> store only the per-letter timing baseline (mean/sigma arrays) and derive
> letter membership during auth from the user's live input — the phrase text
> is not needed server-side at any point.

## Security Analysis

| Phrase                     | Est. bits (no device seed) | With timing layer |
|----------------------------|---------------------------|-------------------|
| 3 common words, 13 letters | 25–30 (human selection bias) | 45–55             |
| 5–6 diceware words         | 64–77                     | 75–90             |
| + device seed (2nd factor) | +128 (device-bound)       | >> 80             |

**Honest caveat:** SPTA is not a replacement for PAKE or FIDO2 in terms of
cryptographic proof strength. Its value is the **input channel** — eliminating
text entry and the attacks that come with it. For maximum security, combine
with a device seed as second factor.

## Build & Run

```sh
gcc -std=c99 -O2 -o spta spta.c -lm
./spta enroll    # register your phrase and capture timing baseline
./spta auth      # authenticate
./spta test      # run self-tests (no phrase input required)
```

Requires: Linux/macOS, gcc, POSIX terminal.

## Self-Test Output

```
=== SPTA Self-Test ===

Test 1: Letter coverage in word list...
  Coverage test: PASS

Test 2: PRNG reproducibility...
  Reproducibility: PASS
  Distinction:     PASS

Test 3: Z-score verification logic...
  z=0.00 AUTH   PASS
  z=1.98 AUTH   PASS
  z=2.00 COERCE PASS
  z=8.00 REJECT PASS
  Z-score test: PASS

=== Self-test complete ===
```

## Prior Art & Positioning

Closest prior work: keystroke dynamics, graphical passwords (PassPoints),
PAKE protocols (SRP, OPAQUE). SPTA differs from all of these in using a
controlled-frequency scrolling word list as the interaction surface, combining
letter-containment verification with timing biometrics on constrained hardware.

The **controlled letter frequency** property (curated word list to equalize
wait time across all 26 letters) is, to the author's knowledge, not present
in prior authentication schemes.

## License

See LICENSE. Non-commercial use free. Commercial use requires permission. Priority: 2026-06-19.

## Discussion

Break it. Seriously. Open an issue.
