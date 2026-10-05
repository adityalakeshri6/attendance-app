const C = 'att-v1';
self.addEventListener('install', e => e.waitUntil(caches.open(C).then(c => c.addAll(['/', '/manifest.json', '/icon-192.png']))));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(k => Promise.all(k.filter(x => x !== C).map(x => caches.delete(x))))));
self.addEventListener('fetch', e => { // network first; never touch API calls
  if (e.request.method !== 'GET' || new URL(e.request.url).pathname.startsWith('/api')) return;
  e.respondWith(fetch(e.request).then(r => { const cp = r.clone(); caches.open(C).then(c => c.put(e.request, cp)); return r; }).catch(() => caches.match(e.request)));
});
