const CACHE_NAME = 'mini-ha-pwa-v2';
const STATIC_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './icon.svg',
  './app.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // 1. Only intercept and cache idempotent GET requests
  if (event.request.method !== 'GET') {
    return;
  }

  // 2. Pass WebSockets and local/cloud API requests through directly to network
  const url = event.request.url;
  if (url.startsWith('ws://') || url.startsWith('wss://') || url.includes('/api/')) {
    return;
  }

  // 3. Stale-while-revalidate / cache-first for static application shell
  event.respondWith(
    fetch(event.request)
      .then((networkResponse) => {
        if (networkResponse && networkResponse.status === 200 && networkResponse.type === 'basic') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return networkResponse;
      })
      .catch(() => {
        return caches.match(event.request);
      })
  );
});
