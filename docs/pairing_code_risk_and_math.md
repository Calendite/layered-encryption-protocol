# Pairing-Code Guessing Risk and Probability Analysis

## Scope

This note analyses the six-character alphanumeric pairing code discussed for the
pairing protocol.

The calculations use these assumptions:

- The code has **six characters**.
- Each character is sampled uniformly from **35 canonical symbols**.
- `0` and `O` represent one canonical symbol.
- A code remains valid for **600 seconds**.
- An attacker receives at most **three online guesses per code**.
- Each fresh code is independent of all previous codes.
- There is no additional cross-session lockout.

The implementation description says that the pairing MAC incorporates a secret
derived from the typed code and that the SAS is derived independently from the
key-exchange result and transcript. The full protocol and implementation must
still be inspected to determine whether a captured MAC acts as an offline
verifier.

## Results at a glance

| Quantity | Result |
|---|---:|
| Code space | `1,838,265,625` |
| Code entropy | `30.78` bits |
| Success probability from 3 online guesses | `1.632e-09` per code |
| Fresh codes needed for 1% cumulative success | `6,158,396` |
| Continuous time for 1% at one code per 10 minutes | `117.1` years |
| Fresh codes needed for 50% cumulative success | `424,729,545` |
| Continuous time for 50% | `8,075` years |
| Offline rate for 1% coverage in 10 minutes | `30,638` guesses/second |
| Offline rate for 50% coverage in 10 minutes | `1,531,888` guesses/second |
| Offline rate for the entire space in 10 minutes | `3,063,776` guesses/second |

## 1. Size of the code space

With 35 possible symbols at each of six positions:

```text
S = 35^6
  = 1,838,265,625
```

The ideal entropy is:

```text
H = log2(S)
  = 6 × log2(35)
  ≈ 30.7757 bits
```

This is slightly under 31 bits.

That is more than enough when an attacker is restricted to only a few online
attempts, but it is not intended to provide cryptographic-key-strength
resistance to an unconstrained offline search.

## 2. Online guessing

With three distinct guesses against one uniformly generated code:

```text
p = 3 / 35^6
  ≈ 1.631973072444e-09
```

This is approximately one success per:

```text
1 / p ≈ 612,755,208 code cycles
```

For a single cycle, the distinction between sampling with and without
replacement is immaterial as long as the attacker does not repeat a guess.

### Cumulative probability

After `n` independent fresh codes, the cumulative probability of at least one
successful guess is:

```text
P(success after n cycles) = 1 - (1 - p)^n
```

Solving for `n` gives:

```text
n = ln(1 - target) / ln(1 - p)
```

For a 1% cumulative probability:

```text
n ≈ 6,158,396 fresh codes
```

At one fresh code every 600 seconds:

```text
time ≈ 6,158,396 × 600 seconds
     ≈ 117.1 years
```

For a 50% cumulative probability:

```text
n ≈ 424,729,545 fresh codes
time ≈ 8,075 years
```

### Online-risk conclusion

Under these assumptions, **online code guessing is not a credible live
threat**. The three-attempt limit is doing most of the security work. The
ten-minute expiry prevents an attacker from carrying unused online attempts
forward indefinitely and limits the opportunity to exploit a successful guess.

The long-term calculation assumes an attacker can continuously obtain a fresh
code every ten minutes without triggering any wider account, device, network,
or abuse lockout. Any such additional limit makes the practical probability
lower.

## 3. Why offline guessing is a separate question

An online rate limit works only when every guess must be submitted to an honest
endpoint that counts and rejects attempts.

An **offline verifier** exists when captured protocol data lets an attacker test
a candidate code locally and determine whether the candidate is correct.
Local guesses are not seen by the endpoint, so the three-attempt restriction
does not apply.

The protocol description gives the pairing MAC in the following form:

```text
K_handshake = HKDF(shared secret, transcript, pairing label)
codeSecret  = HKDF(code, no salt, code-secret label)

MAC = HMAC(K_handshake || codeSecret, transcript || role)
```

A possible concern is an active intermediary who substitutes key-exchange
material on one leg. If this lets the intermediary know that leg's
`K_handshake`, the observed MAC may allow candidate codes to be checked
locally.

This is a **conditional protocol question**, not a demonstrated vulnerability
from the implementation description alone. It must be validated against:

- the exact key-exchange roles;
- all transcript fields;
- when MACs are sent;
- whether failed sessions can be continued;
- how the expiry is enforced;
- whether the attacker can use a recovered code before the session closes.

## 4. What the 600-second expiry means offline

If an offline verifier exists, expiry does not cap the number of computations.
It caps the time available to recover and use the code.

For a uniformly random target, testing `g` distinct candidates gives
approximately:

```text
P(success) = g / S
```

provided `g` does not exceed the code space.

### Rates needed within 600 seconds

To cover 1% of the space:

```text
0.01 × S / 600
≈ 30,638 guesses per second
```

To cover half of the space, corresponding to about a 50% success probability:

```text
0.50 × S / 600
≈ 1,531,888 guesses per second
```

To exhaust the entire space:

```text
S / 600
≈ 3,063,776 guesses per second
```

These values are **required rates**, not measurements of a real attack.
Actual throughput depends on the exact HKDF/HMAC implementation, hardware,
parallelism, transcript handling, and whether the attack model is valid.

Because HKDF-SHA256 and HMAC-SHA256 are intentionally fast primitives, the
offline case should be settled by:

1. verifying whether an offline verifier actually exists; and
2. benchmarking the complete candidate-check operation on representative
   hardware.

A password-hardening function would slow guessing, but replacing protocol
components ad hoc is not recommended. A standard PAKE is the conventional
solution when a low-entropy secret itself must resist offline verification.

## 5. Recovering the code is not necessarily a complete pairing break

The protocol also derives a six-digit SAS independently from the shared secret
and transcript.

If an intermediary establishes two different key exchanges, the two sides
should display different SAS values. Assuming the SAS is uniformly distributed,
the chance of an accidental match in one independent attempt is:

```text
1 / 10^6 = 0.000001
```

Therefore, even successful code recovery does not automatically bypass a
correctly performed human SAS comparison.

The remaining risks include:

- the users failing to compare all six digits;
- confusing or misleading confirmation UI;
- repeated sessions allowing repeated SAS attempts;
- an attacker grinding key exchanges or transcripts to seek a SAS collision;
- one endpoint being compromised and displaying a false value.

The feasibility of SAS grinding depends on the exact state machine and the cost
of producing candidate X-Wing exchanges. It should be analysed separately
rather than assumed either practical or impossible.

## 6. Important uniformity caveat

The calculation `35^6` assumes the generator samples **directly and uniformly**
from 35 canonical symbols.

There is a different implementation that looks similar but is not uniform:

1. sample uniformly from all 36 alphanumeric symbols;
2. generate either `0` or `O`;
3. fold both results into one displayed symbol.

In that construction, the folded symbol occurs with probability:

```text
2 / 36 = 1 / 18
```

Every ordinary symbol occurs with probability:

```text
1 / 36
```

The most likely six-character code, consisting entirely of the folded symbol,
then has probability:

```text
(1 / 18)^6 ≈ 2.940119411186e-08
```

Its min-entropy is only:

```text
-log2((1 / 18)^6) ≈ 25.02 bits
```

The three most likely guesses together have probability approximately:

```text
5.880238822372e-08
```

Under continuous fresh-code cycling, that biased top-three probability would
reach 1% after approximately:

```text
170,917 cycles
≈ 3.25 years at ten minutes per cycle
```

That is still a small online risk, but it is materially different from the
uniform-35 calculation.

### Correct generation method

Generate each position by sampling uniformly from a predefined array containing
exactly 35 canonical symbols. Do not generate from 36 symbols and fold after
selection.

A rejection-sampling implementation is also acceptable if it produces exactly
uniform output.

## 7. Practical risk assessment

### Online guessing

**Low/negligible**, provided:

- the generator is uniform over 35 canonical symbols;
- only three guesses are accepted for each code;
- the code expires after 600 seconds;
- attempts cannot be reset cheaply inside the same pairing;
- fresh-code creation is not an unauthenticated resource-exhaustion vector.

### Offline guessing

**Unresolved from the implementation description alone.**

The relevant issue is not merely the 30.8-bit code space. It is whether an
active attacker can obtain a reliable offline verifier and then use a recovered
code while the session remains valid.

### SAS bypass

**Independent residual risk.**

A recovered code still should not let an intermediary silently complete pairing
when both users correctly compare the six-digit SAS. The state machine should
limit retries and make mismatches terminal.

## 8. Recommended checks

1. Confirm that code characters are sampled uniformly from exactly 35 canonical
   symbols.
2. Confirm that the three-attempt limit cannot be reset within one code's
   lifetime.
3. Confirm expiry is checked by the authoritative endpoint, not only by the UI.
4. Model an active intermediary that substitutes X-Wing material independently
   toward both devices.
5. Determine whether either captured MAC provides an offline code verifier.
6. Benchmark the complete candidate-verification path if such a verifier exists.
7. Make an incorrect SAS comparison terminate the session.
8. Limit how many fresh sessions can be created by one source.
9. Log or surface repeated failed pairing attempts without exposing sensitive
   transcript data.
10. Include the code-generation and expiry behaviour in protocol tests.

## 9. Python used for these calculations

```python
import math

# Inputs
ALPHABET_SIZE = 35
CODE_LENGTH = 6
ONLINE_GUESSES_PER_CODE = 3
CODE_LIFETIME_SECONDS = 600

space = ALPHABET_SIZE ** CODE_LENGTH
entropy_bits = math.log2(space)
online_probability_per_code = ONLINE_GUESSES_PER_CODE / space

def cycles_for_probability(target_probability: float) -> float:
    """Fresh-code cycles needed to reach a cumulative success probability."""
    return (
        math.log1p(-target_probability)
        / math.log1p(-online_probability_per_code)
    )

cycles_for_one_percent = cycles_for_probability(0.01)
cycles_for_fifty_percent = cycles_for_probability(0.50)

seconds_per_year = 365.25 * 24 * 60 * 60

years_for_one_percent = (
    cycles_for_one_percent
    * CODE_LIFETIME_SECONDS
    / seconds_per_year
)

years_for_fifty_percent = (
    cycles_for_fifty_percent
    * CODE_LIFETIME_SECONDS
    / seconds_per_year
)

# Offline rates needed to search a given fraction before expiry.
offline_rate_one_percent = (
    0.01 * space / CODE_LIFETIME_SECONDS
)
offline_rate_fifty_percent = (
    0.50 * space / CODE_LIFETIME_SECONDS
)
offline_rate_full_space = (
    space / CODE_LIFETIME_SECONDS
)

print(f"Space: {space:,}")
print(f"Entropy: {entropy_bits:.4f} bits")
print(
    "Online probability per code: "
    f"{online_probability_per_code:.12e}"
)
print(
    "Cycles for 1%: "
    f"{cycles_for_one_percent:,.0f}"
)
print(
    "Years for 1%: "
    f"{years_for_one_percent:,.2f}"
)
print(
    "Cycles for 50%: "
    f"{cycles_for_fifty_percent:,.0f}"
)
print(
    "Years for 50%: "
    f"{years_for_fifty_percent:,.2f}"
)
print(
    "Offline rate for 1% in 600 seconds: "
    f"{offline_rate_one_percent:,.0f} guesses/s"
)
print(
    "Offline rate for 50% in 600 seconds: "
    f"{offline_rate_fifty_percent:,.0f} guesses/s"
)
print(
    "Offline rate for full search in 600 seconds: "
    f"{offline_rate_full_space:,.0f} guesses/s"
)

# Conditional bias analysis:
# Generate from 36 symbols, then fold 0 and O afterwards.
folded_symbol_probability = 2 / 36
ordinary_symbol_probability = 1 / 36

most_likely_code_probability = (
    folded_symbol_probability ** CODE_LENGTH
)

next_tier_probability = (
    folded_symbol_probability ** (CODE_LENGTH - 1)
    * ordinary_symbol_probability
)

# Best guess: all folded symbols.
# The next two guesses can be any two codes containing five folded
# symbols and one ordinary symbol.
biased_top_three_probability = (
    most_likely_code_probability
    + 2 * next_tier_probability
)

biased_min_entropy_bits = -math.log2(
    most_likely_code_probability
)

biased_cycles_for_one_percent = (
    math.log1p(-0.01)
    / math.log1p(-biased_top_three_probability)
)

biased_years_for_one_percent = (
    biased_cycles_for_one_percent
    * CODE_LIFETIME_SECONDS
    / seconds_per_year
)

print(
    "Biased top-three probability: "
    f"{biased_top_three_probability:.12e}"
)
print(
    "Biased min-entropy: "
    f"{biased_min_entropy_bits:.4f} bits"
)
print(
    "Biased cycles for 1%: "
    f"{biased_cycles_for_one_percent:,.0f}"
)
print(
    "Biased years for 1%: "
    f"{biased_years_for_one_percent:,.2f}"
)
```

## Conclusion

The stated limits make **online guessing negligible** under uniform generation.
The central unresolved concern is whether an active intermediary can turn a
captured pairing MAC into an **offline code verifier**.

Even if offline recovery is possible, the independent six-digit SAS is intended
to prevent silent intermediary pairing. The complete risk therefore depends on
three separate controls:

1. code entropy and expiry;
2. whether offline verification is possible;
3. whether SAS comparison and retry handling remain effective.
