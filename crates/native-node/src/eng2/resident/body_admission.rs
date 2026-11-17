//! Bounded decoded-body ownership, separate from bidirectional socket turns.
use super::*;
use std::collections::VecDeque;
use std::sync::{
    Condvar,
    atomic::{AtomicU64, Ordering},
};
const CAPACITY: usize = 4;
struct Mailbox<T> {
    queue: Mutex<VecDeque<T>>,
    ready: Condvar,
}
impl<T> Default for Mailbox<T> {
    fn default() -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(CAPACITY)),
            ready: Condvar::new(),
        }
    }
}
impl<T> Mailbox<T> {
    fn submit(&self, value: T) -> Result<(), T> {
        let Ok(mut queue) = self.queue.lock() else {
            return Err(value);
        };
        if queue.len() >= CAPACITY {
            return Err(value);
        }
        queue.push_back(value);
        self.ready.notify_one();
        Ok(())
    }
    fn take(&self, cancel: &p2p::Cancellation) -> Result<Option<T>, String> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| "decoded body queue lock poisoned")?;
        loop {
            if cancel.is_cancelled() {
                queue.clear();
                return Ok(None);
            }
            if let Some(job) = queue.pop_front() {
                return Ok(Some(job));
            }
            queue = self
                .ready
                .wait_timeout(queue, Duration::from_millis(50))
                .map_err(|_| "decoded body queue lock poisoned")?
                .0;
        }
    }
}
pub(super) struct Ready {
    pub download: header_lane::Download,
    pub received: super::super::transport::ReceivedBody,
    pub path: Vec<super::super::header::Header>,
}
#[derive(Default)]
pub(super) struct Queue {
    mailbox: Mailbox<Ready>,
    completed: AtomicU64,
    rejected: AtomicU64,
    deferred: AtomicU64,
}
impl Queue {
    pub(super) fn clear(&self) -> Result<(), String> {
        self.mailbox
            .queue
            .lock()
            .map_err(|_| "decoded body queue lock poisoned")?
            .clear();
        Ok(())
    }
    pub(super) fn diagnostic(&self) -> Value {
        json!({"scope":"decoded_body_jobs","completed_retention":self.completed.load(Ordering::Relaxed),"rejected":self.rejected.load(Ordering::Relaxed),"deferred":self.deferred.load(Ordering::Relaxed),"native_acceptance_not_implied":true})
    }
    pub(super) fn submit(&self, ready: Ready) {
        if ready.received.ownership.check_active().is_err() || self.mailbox.submit(ready).is_err() {
            self.deferred.fetch_add(1, Ordering::Relaxed);
        }
    }
}
#[cfg(test)]
pub(super) fn test_take(queue: &Queue) -> Ready {
    queue.mailbox.queue.lock().unwrap().pop_front().unwrap()
}
#[cfg(test)]
pub(super) fn test_admit(shared: &Shared, ready: &Ready) -> Result<bool, String> {
    admit(shared, ready)
}
pub(super) fn run(shared: Arc<Shared>) -> Result<(), String> {
    while let Some(ready) = shared.bodies.mailbox.take(&shared.cancel)? {
        if ready.download.cancel.is_cancelled()
            || ready.received.ownership.check_active().is_err()
            || shared.headers.error().is_some()
        {
            continue;
        }
        let result = admit(&shared, &ready);
        match result {
            Ok(true) => {
                ready.received.ownership.complete();
                shared.headers.completed(&ready.download.header)?;
                shared.bodies.completed.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {
                shared.bodies.deferred.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                // Invalid native material remains rejected by the existing
                // owner observer. No speculative state or retry is supplied.
                shared.headers.rejected(&ready.download.header)?;
                shared.bodies.rejected.fetch_add(1, Ordering::Relaxed);
            }
        }
        // The decoded buffer charge and download lease move together through
        // the complete native admission/retention operation, then drop here.
    }
    Ok(())
}
fn admit(shared: &Shared, ready: &Ready) -> Result<bool, String> {
    use super::super::network::Owner;
    let header = &ready.download.header;
    let mut owner = shared
        .owner
        .lock()
        .map_err(|_| "resident owner lock poisoned")?;
    if ready.download.cancel.is_cancelled()
        || ready.received.ownership.check_active().is_err()
        || !owner.activities_allowed()
    {
        return Ok(false);
    }
    owner.retain_fast_headers(&ready.path)?;
    let head = owner.head()?;
    if head.height.checked_add(1) == Some(header.height) && head.id == header.parent {
        owner.accept_received(header, &ready.received)?;
        Ok(true)
    } else if head.height >= header.height && owner.header(header.height)?.id() == header.id() {
        Ok(true)
    } else {
        owner.retain_fast_body(header, &ready.received.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Owned(Arc<AtomicUsize>);
    impl Drop for Owned {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn bounded_queue_returns_excess_ownership_and_shutdown_drains_queued_leases() {
        let count = Arc::new(AtomicUsize::new(0));
        let queue = Mailbox::default();
        for _ in 0..CAPACITY {
            assert!(queue.submit(Owned(count.clone())).is_ok());
        }
        let excess = queue.submit(Owned(count.clone())).err().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        drop(excess);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let cancel = p2p::Cancellation::default();
        cancel.cancel();
        assert!(queue.take(&cancel).unwrap().is_none());
        assert_eq!(count.load(Ordering::SeqCst), CAPACITY + 1);
    }
    #[test]
    fn decoded_queue_wakes_its_retained_consumer_and_never_duplicates_a_job() {
        let queue = Arc::new(Mailbox::default());
        let cancel = p2p::Cancellation::default();
        let consumer = queue.clone();
        let stop = cancel.clone();
        let (result, receive) = std::sync::mpsc::sync_channel(1);
        let handle =
            std::thread::spawn(move || result.send(consumer.take(&stop).unwrap()).unwrap());
        assert!(queue.submit(7).is_ok());
        let value = receive.recv_timeout(Duration::from_secs(1));
        cancel.cancel();
        handle.join().unwrap();
        assert_eq!(value.unwrap(), Some(7));
        cancel.cancel();
        assert!(queue.take(&cancel).unwrap().is_none());
    }
}
