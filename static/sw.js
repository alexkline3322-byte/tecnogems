// TecnoGems Service Worker — V42 batch2
// Strategy:
//  - HTML pages: NetworkFirst (always try fresh, fallback to cache for offline)
//  - Static assets (css/js/img/fonts): CacheFirst with background revalidate
//  - Never cache API or admin routes
const CACHE_VERSION = 'tg-v48-1';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const PAGES_CACHE = `${CACHE_VERSION}-pages`;
const OFFLINE_URL = '/';

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) =>
      cache.addAll([
        '/static/css/style.min.css',
        '/static/css/v40-improvements.css',
        '/static/css/v41-polish.css',
        '/static/js/app.min.js',
        '/static/img/tecnogems-logo.webp',
        '/static/img/logo-32.webp',
      ]).catch(() => {})
    ).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => !k.startsWith(CACHE_VERSION)).map((k) => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

function shouldBypass(url) {
  return (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/admin') ||
    url.pathname.startsWith('/auth/') ||
    url.pathname.startsWith('/login') ||
    url.pathname.startsWith('/logout') ||
    url.pathname.startsWith('/checkout') ||
    url.pathname.startsWith('/wallet') ||
    url.pathname.startsWith('/profile') ||
    url.pathname.startsWith('/orders') ||
    url.pathname.startsWith('/uploads/')
  );
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (shouldBypass(url)) return;

  // HTML navigations: NetworkFirst
  if (req.mode === 'navigate' || (req.headers.get('accept') || '').includes('text/html')) {
    event.respondWith(
      fetch(req).then((res) => {
        const copy = res.clone();
        caches.open(PAGES_CACHE).then((c) => c.put(req, copy));
        return res;
      }).catch(() =>
        caches.match(req).then((hit) => hit || caches.match(OFFLINE_URL))
      )
    );
    return;
  }

  // Static assets: CacheFirst
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(req).then((hit) => {
        if (hit) {
          fetch(req).then((res) => {
            caches.open(STATIC_CACHE).then((c) => c.put(req, res.clone()));
          }).catch(() => {});
          return hit;
        }
        return fetch(req).then((res) => {
          const copy = res.clone();
          caches.open(STATIC_CACHE).then((c) => c.put(req, copy));
          return res;
        });
      })
    );
  }
});
