//! Separate bounded budgets leave room for management while proxies are busy.
use std::sync::atomic::{AtomicUsize, Ordering};
static CLIENTS: AtomicUsize = AtomicUsize::new(0);
static PROXIES: AtomicUsize = AtomicUsize::new(0);
static HEADERS: AtomicUsize = AtomicUsize::new(0);
static API: AtomicUsize = AtomicUsize::new(0);
pub(crate) struct Permit(&'static AtomicUsize);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(crate) fn reserve(counter: &AtomicUsize, maximum: usize) -> bool {
    let mut count = counter.load(Ordering::Acquire);
    while count < maximum {
        match counter.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => count = actual,
        }
    }
    false
}
fn take(counter: &'static AtomicUsize, maximum: usize) -> Option<Permit> {
    reserve(counter, maximum).then(|| Permit(counter))
}
pub(crate) fn client() -> Option<Permit> {
    take(&CLIENTS, 512)
}
pub(crate) fn proxy() -> Option<Permit> {
    take(&PROXIES, 384)
}
pub(crate) fn headers() -> Option<Permit> {
    take(&HEADERS, 64)
}
pub(crate) fn api() -> Option<Permit> {
    take(&API, 64)
}
