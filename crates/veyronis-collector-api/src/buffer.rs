use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use veyronis_ir::event::VirEvent;

/// Bounded telemetry event buffer with atomic drop counter.
#[derive(Clone)]
pub struct EventRingBuffer {
    sender: Sender<VirEvent>,
    receiver: Arc<Mutex<Receiver<VirEvent>>>,
    capacity: usize,
    dropped_count: Arc<AtomicUsize>,
    total_received: Arc<AtomicUsize>,
}

impl EventRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = bounded(capacity);
        Self {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            capacity,
            dropped_count: Arc::new(AtomicUsize::new(0)),
            total_received: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn push(&self, event: VirEvent) -> bool {
        self.total_received.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn drain(&self, max_items: usize) -> Vec<VirEvent> {
        let rx = self.receiver.lock();
        let mut items = Vec::with_capacity(max_items.min(self.capacity));
        for _ in 0..max_items {
            match rx.try_recv() {
                Ok(item) => items.push(item),
                Err(_) => break,
            }
        }
        items
    }

    pub fn dropped_count(&self) -> usize {
        self.dropped_count.load(Ordering::Relaxed)
    }

    pub fn total_received(&self) -> usize {
        self.total_received.load(Ordering::Relaxed)
    }
}
