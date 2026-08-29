pub mod buffer;
pub mod capabilities;
pub mod error;
pub mod health;
pub mod target;
pub mod traits;

pub use buffer::EventRingBuffer;
pub use capabilities::{CapabilityLevel, CollectorCapabilities};
pub use error::CollectorError;
pub use health::CollectorHealth;
pub use target::TargetProcess;
pub use traits::Collector;

#[cfg(test)]
mod tests {
    use super::*;
    use veyronis_ir::categories::{EventData, ProcessStartData};
    use veyronis_ir::event::{EventType, VirEvent};
    use veyronis_ir::identity::ProcessIdentity;

    #[test]
    fn test_event_ring_buffer_bounded_capacity() {
        let buffer = EventRingBuffer::new(2);
        let proc = ProcessIdentity::new(10, None, 0, "test", 1);
        let event = VirEvent::new(
            proc,
            EventType::ProcessStart,
            EventData::ProcessStart(ProcessStartData {
                executable_path: "test".into(),
                command_line: vec![],
                working_directory: None,
                parent_pid: None,
                environment_keys: vec![],
            }),
            "test",
        );

        assert!(buffer.push(event.clone()));
        assert!(buffer.push(event.clone()));
        // Buffer is full; 3rd push should drop and record statistic
        assert!(!buffer.push(event.clone()));

        assert_eq!(buffer.dropped_count(), 1);
        assert_eq!(buffer.total_received(), 3);

        let drained = buffer.drain(10);
        assert_eq!(drained.len(), 2);
    }
}
