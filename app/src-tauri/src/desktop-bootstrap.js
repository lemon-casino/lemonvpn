// Embedded assets already work offline. A PWA worker from an older desktop
// release can keep serving an outdated UI after the executable is upgraded.
window.__LEMONVPN_DESKTOP_READY__ = (async () => {
  try {
    const workers = navigator.serviceWorker;
    if (!workers) return;
    const controlled = !!workers.controller;
    const registrations = await workers.getRegistrations();
    const removed = await Promise.all(registrations.map(registration => {
      const script = registration.active?.scriptURL ?? registration.waiting?.scriptURL ?? registration.installing?.scriptURL;
      if (!script) return false;
      const url = new URL(script);
      return url.origin === location.origin && url.pathname === '/sw.js' ? registration.unregister() : false;
    }));
    if ('caches' in window) {
      const keys = await caches.keys();
      await Promise.all(keys.filter(key => key.startsWith(`doona-shell:${location.origin}/:`)).map(key => caches.delete(key)));
    }
    if (controlled && removed.some(Boolean)) location.reload();
  } catch (error) {
    console.warn('LemonVPN frontend cache migration failed:', error);
  }
})();
