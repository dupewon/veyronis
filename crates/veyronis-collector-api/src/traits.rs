use crate::capabilities::CollectorCapabilities;
use crate::error::CollectorError;
use crate::health::CollectorHealth;
use crate::target::TargetProcess;
use veyronis_ir::event::VirEvent;

/// Master interface for platform-specific telemetry collectors.
pub trait Collector: Send + Sync {
    /// Human-readable collector identifier.
    fn name(&self) -> &'static str;

    /// Current capability ratings for this collector on the host system.
    fn capabilities(&self) -> CollectorCapabilities;

    /// Initializes collector subsystems and validates OS permissions.
    fn initialize(&mut self) -> Result<(), CollectorError>;

    /// Starts telemetry collection attached to the target process tree.
    fn start(&mut self, target: &TargetProcess) -> Result<(), CollectorError>;

    /// Polls buffered normalized VIR events up to `max_events`.
    fn poll_events(&mut self, max_events: usize) -> Result<Vec<VirEvent>, CollectorError>;

    /// Stops collection and returns health summary.
    fn stop(&mut self) -> Result<CollectorHealth, CollectorError>;

    /// Returns live operational metrics.
    fn health(&self) -> CollectorHealth;
}
