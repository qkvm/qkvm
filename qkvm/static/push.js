'use strict';

// qKVM's service worker. It shows the alerts the wall tells this browser by Web Push, and opens the wall at the tile a
// tap is about; and nothing else. No request of the page goes through it: it has no fetch handler, and its scope
// (static/push/) holds no page. It keeps nothing and takes in no other script. What an alert says arrives encrypted
// for this browser alone; the browser opens it before it is handed to this worker.

const TILE = /^[A-Za-z0-9_-]{1,40}$/;  // a tile's id, as the page takes one from the address (#tile=...)

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('push', event => {
  let said = {};
  try {
    said = event.data ? event.data.json() : {};
  } catch {
    said = {};  // (not what the wall sends: shown as an alert all the same, as a browser asks every push to be)
  }
  const text = value => (typeof value === 'string' ? value : '');
  const tile = TILE.test(text(said?.tile)) ? said.tile : '';
  event.waitUntil(self.registration.showNotification(text(said?.title).slice(0, 120) || 'qKVM', {
    body: text(said?.body).slice(0, 400),
    timestamp: Number.isFinite(said?.at) ? said.at * 1000 : Date.now(),
    data: { tile },
  }));
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  // The wall is the folder above this worker's own (static/push.js), wherever the wall is served from.
  const wall = new URL('..', self.location.href);
  const tile = event.notification.data?.tile;
  if (tile && TILE.test(tile)) wall.hash = `tile=${tile}`;
  event.waitUntil(self.clients.openWindow(wall.href));
});
