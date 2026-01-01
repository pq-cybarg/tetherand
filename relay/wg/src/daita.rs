//! DAITA — Defense Against AI-guided Traffic Analysis.
//!
//! Wraps maybenot 2.2's `Framework`. The framework's TriggerAction enum
//! doesn't carry a padding-byte-size — Mullvad's design assumes the
//! caller pads to the link MTU when SendPadding fires. We follow that
//! convention (1280-byte padding packets, matching the WG MTU we use).
//!
//! The BlockOutgoing action is logged but not enforced in this MVP
//! (the WG hop's encap pump would need to integrate the duration
//! distribution sampler; tracked for follow-up).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use maybenot::{Framework, Machine, TriggerAction, TriggerEvent};
use rand9::SeedableRng;
use rand9::rngs::StdRng;

const PADDING_BYTES: u16 = 1280;

pub struct DaitaScheduler {
    inner: Mutex<Framework<Vec<Machine>, StdRng, Instant>>,
}

impl DaitaScheduler {
    pub fn new(machines_bytes: &[&[u8]]) -> Result<Self, String> {
        let mut machines: Vec<Machine> = Vec::with_capacity(machines_bytes.len());
        for raw in machines_bytes {
            let s = std::str::from_utf8(raw)
                .map_err(|e| format!("maybenot machine not utf-8: {e:?}"))?;
            let m: Machine = s.parse()
                .map_err(|e| format!("maybenot machine parse: {e:?}"))?;
            machines.push(m);
        }
        // Seed StdRng from the OS — satisfies maybenot's RngCore bound.
        let rng = StdRng::from_os_rng();
        let framework = Framework::new(
            machines,
            /* max_padding_frac = */ 0.5,
            /* max_blocking_frac = */ 0.0,
            Instant::now(),
            rng,
        )
        .map_err(|e| format!("maybenot framework: {e:?}"))?;
        Ok(Self { inner: Mutex::new(framework) })
    }

    pub fn on_packet_sent(&self, _size: u16) -> Vec<PaddingAction> {
        let mut fw = self.inner.lock().expect("poisoned");
        Self::drain(&mut fw, &[TriggerEvent::NormalSent])
    }

    pub fn on_packet_recv(&self, _size: u16) -> Vec<PaddingAction> {
        let mut fw = self.inner.lock().expect("poisoned");
        Self::drain(&mut fw, &[TriggerEvent::NormalRecv])
    }

    /// Periodic tick. Drives any time-based scheduling that the
    /// framework needs to emit between real-packet events.
    pub fn tick(&self) -> Vec<PaddingAction> {
        let mut fw = self.inner.lock().expect("poisoned");
        Self::drain(&mut fw, &[])
    }

    fn drain(
        fw: &mut Framework<Vec<Machine>, StdRng, Instant>,
        events: &[TriggerEvent],
    ) -> Vec<PaddingAction> {
        let now = Instant::now();
        let mut out = Vec::new();
        for action in fw.trigger_events(events, now) {
            match action {
                TriggerAction::SendPadding { .. } => {
                    out.push(PaddingAction::SendPadding(PADDING_BYTES));
                }
                TriggerAction::BlockOutgoing { .. } => {
                    // BlockOutgoing carries a Dist for duration; sampling
                    // would require borrowing the Framework's RNG. For
                    // this MVP we report a fixed token block (50ms) and
                    // let the caller enforce or log.
                    out.push(PaddingAction::BlockOutgoing(Duration::from_millis(50)));
                }
                _ => {}
            }
        }
        out
    }
}

#[derive(Debug)]
pub enum PaddingAction {
    SendPadding(u16),
    BlockOutgoing(Duration),
}
