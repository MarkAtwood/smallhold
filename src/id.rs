use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static STATE: AtomicU64 = AtomicU64::new(0);

pub fn generate_id() -> i64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock went backwards")
        .as_millis() as u64;

    loop {
        let prev = STATE.load(Ordering::Acquire);
        let prev_ms = prev >> 16;
        let prev_seq = prev & 0xFFFF;

        let (ms, seq) = if now_ms <= prev_ms {
            // Clock same or went backward (NTP adjustment): stay monotonic
            if prev_seq >= 0xFFFF {
                // Sequence exhausted for this millisecond, spin
                std::hint::spin_loop();
                continue;
            }
            (prev_ms, prev_seq + 1)
        } else {
            (now_ms, 0)
        };

        let new_state = (ms << 16) | seq;
        if STATE
            .compare_exchange(prev, new_state, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return ((ms << 16) | seq) as i64;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic() {
        let mut prev = 0i64;
        for _ in 0..1000 {
            let id = generate_id();
            assert!(id > prev, "ID {id} not greater than {prev}");
            prev = id;
        }
    }

    #[test]
    fn ids_are_positive() {
        for _ in 0..100 {
            assert!(generate_id() > 0);
        }
    }

    #[test]
    fn id_serializes_as_string() {
        let id = generate_id();
        let s = id.to_string();
        assert!(s.parse::<i64>().is_ok());
    }
}
