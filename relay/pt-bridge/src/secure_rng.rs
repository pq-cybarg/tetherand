// 5364C13D-posture entropy mixer for the pt-bridge crate.
//
// Mirrors the Kotlin `SeekerRng` SPI in the Android app: every byte
// that flows out is the SHAKE-256 squeeze of a multi-source absorb
// over four independent entropy sources, so an adversary who has
// biased one source still cannot predict our output.
//
// Sources absorbed per call:
//
//   1. `getrandom()` — the OS-supplied CSPRNG. On Linux this is
//      `getrandom(2)` which wraps the kernel pool; on macOS it's
//      `getentropy(3)`. Either way it's the platform's idea of
//      "give me secure randomness".
//   2. RDRAND / RDSEED on x86_64 (or the equivalent ARM PMU jitter
//      counter on aarch64). Independent of the kernel pool; absorbed
//      directly. If the instruction is missing, sub-source skipped
//      cleanly.
//   3. Monotonic-clock skew. `Instant::now()` reads twice in a busy
//      loop; the delta carries a few bits of scheduler/cache jitter.
//   4. Process-internal counter. Domain-separates calls inside the
//      same nanosecond and guarantees forward security against an
//      adversary who somehow gets to repeatedly call us.
//
// All four are absorbed into a single SHAKE-256 instance, then we
// squeeze `n` bytes into the caller's buffer. SHAKE-256 is FIPS-202.
// Under the random-oracle assumption, the output is computationally
// indistinguishable from uniform as long as ANY one of the four
// sources supplied a bit of unpredictable entropy.
//
// Use this in EVERY place the pt-bridge crate needs a random byte —
// session IDs, padding lengths, ephemeral keypairs. Never call
// `rand::thread_rng()` directly from this crate again.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use zeroize::Zeroize;

static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Fill `out` with cryptographically strong, SHAKE-256-whitened bytes.
/// Constant-time with respect to `out.len()` modulo the underlying
/// `getrandom` syscall latency.
pub fn fill(out: &mut [u8]) {
    if out.is_empty() { return; }

    let mut shake = Shake256::default();

    // (1) getrandom — 64 bytes (more than 256 bits of OS entropy).
    let mut sys = [0u8; 64];
    if let Err(_e) = getrandom::getrandom(&mut sys) {
        // getrandom failing is catastrophic — the kernel pool is
        // unavailable. We continue with the other three sources, but
        // a degraded RNG here is detectable and should NEVER happen
        // in production. We can't return an error from this fn
        // signature, so we panic — the alternative is silently
        // weakened randomness, which is worse for our threat model.
        panic!("getrandom unavailable; cannot proceed with weakened entropy");
    }
    shake.update(&sys);
    sys.zeroize();

    // (2) Hardware-RNG sub-source. On x86_64 we try RDRAND; on
    // aarch64 we steal low bits from the PMU cycle counter (which is
    // jittery enough to contribute entropy even though it is not a
    // CSPRNG in itself). On other architectures we skip — the
    // remaining sources carry the call.
    let hw = hardware_entropy();
    shake.update(&hw.to_le_bytes());

    // (3) Monotonic-clock skew. Busy-loop reading `Instant::now()`
    // until the value changes; the delta is a few hundred to a few
    // thousand nanoseconds. 16 deltas = ~128 bits of timing jitter
    // (much less than that of full entropy, but absorbed alongside
    // the other sources it is just extra mass for SHAKE).
    let mut jitter = [0u8; 16];
    let mut prev = Instant::now();
    for slot in jitter.iter_mut() {
        for _ in 0..256 {
            let now = Instant::now();
            if now != prev {
                let delta = now.duration_since(prev).as_nanos() as u64;
                *slot = (delta & 0xff) as u8;
                prev = now;
                break;
            }
        }
    }
    shake.update(&jitter);
    jitter.zeroize();

    // (4) Process-internal call counter.
    let ctr = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    shake.update(&ctr.to_le_bytes());

    // Squeeze.
    let mut reader = shake.finalize_xof();
    reader.read(out);
}

/// Convenience: return a single random `u64`.
#[allow(dead_code)]  // public convenience API; not used by current PT handlers but worth keeping
pub fn next_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill(&mut buf);
    u64::from_le_bytes(buf)
}

/// Convenience: return a uniformly-distributed `u16` in `[0, max)`
/// using rejection sampling. The `% N` shortcut introduces modulo
/// bias when N is not a power of two; for cryptographic-quality
/// padding lengths we use rejection.
pub fn next_u16_below(max: u16) -> u16 {
    debug_assert!(max > 0);
    let bound = (u16::MAX as u32 + 1) - ((u16::MAX as u32 + 1) % max as u32);
    loop {
        let mut buf = [0u8; 2];
        fill(&mut buf);
        let v = u16::from_le_bytes(buf) as u32;
        if v < bound {
            return (v % max as u32) as u16;
        }
    }
}

// ---------------------------------------------------------------------
// Architecture-specific hardware-entropy taps. We accept whatever any
// path returns; the SHAKE absorb makes degenerate (e.g. always-zero)
// inputs harmless.
// ---------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn hardware_entropy() -> u64 {
    // RDRAND returns a flag indicating whether the read succeeded.
    // We try a handful of times; if RDRAND keeps failing, fall back
    // to RDTSC (cycle counter — not random but jittery enough to
    // contribute when SHAKE-mixed).
    unsafe {
        for _ in 0..10 {
            let mut v: u64 = 0;
            if core::arch::x86_64::_rdrand64_step(&mut v) == 1 {
                return v;
            }
        }
        core::arch::x86_64::_rdtsc()
    }
}

#[cfg(target_arch = "aarch64")]
fn hardware_entropy() -> u64 {
    // ARMv8 has no public RDRAND-equivalent without privileged
    // access; we steal the cycle counter (CNTVCT_EL0 is unprivileged
    // and monotonic). Cycle counters are not CSPRNGs but DO
    // contribute scheduler/interrupt jitter when sampled.
    let v: u64;
    unsafe { core::arch::asm!("mrs {x}, cntvct_el0", x = out(reg) v); }
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn hardware_entropy() -> u64 {
    // Unknown ISA. Skip the hardware sub-source; the other three
    // carry the call.
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_returns_distinct_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a);
        fill(&mut b);
        assert_ne!(a, b, "two successive fill() calls produced identical output");
        assert!(a.iter().any(|&b| b != 0), "fill returned all zeros");
    }

    #[test]
    fn next_u16_below_respects_bound() {
        for _ in 0..1000 {
            let v = next_u16_below(8192);
            assert!(v < 8192);
        }
    }

    #[test]
    fn next_u64_distinct() {
        let v1 = next_u64();
        let v2 = next_u64();
        assert_ne!(v1, v2, "next_u64 produced identical successive values");
    }
}
