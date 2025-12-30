// Service Worker for WealthWise PWA
const CACHE_NAME = 'wealthwise-v1.0.0'
const RUNTIME_CACHE = 'wealthwise-runtime'

// Assets to cache on install
const PRECACHE_ASSETS = [
    '/',
    '/dashboard',
    '/offline',
    '/manifest.json',
    '/icons/icon-192x192.png',
    '/icons/icon-512x512.png'
]

// Install event - cache essential assets
self.addEventListener('install', (event) => {
    console.log('[Service Worker] Installing...')
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => {
                console.log('[Service Worker] Precaching assets')
                return cache.addAll(PRECACHE_ASSETS)
            })
            .then(() => self.skipWaiting())
    )
})

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('[Service Worker] Activating...')
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME && name !== RUNTIME_CACHE)
                    .map((name) => {
                        console.log('[Service Worker] Deleting old cache:', name)
                        return caches.delete(name)
                    })
            )
        }).then(() => self.clients.claim())
    )
})

// Fetch event - network first, then cache
self.addEventListener('fetch', (event) => {
    const { request } = event

    // Skip non-GET requests
    if (request.method !== 'GET') return

    // Skip chrome extensions
    if (request.url.startsWith('chrome-extension://')) return

    // Skip analytics and external APIs
    if (
        request.url.includes('analytics') ||
        request.url.includes('googleapis') ||
        request.url.includes('gstatic')
    ) return

    // Handle API calls - network only with fallback
    if (request.url.includes('/api/')) {
        event.respondWith(
            fetch(request)
                .catch(() => {
                    return new Response(
                        JSON.stringify({ error: 'Offline - Please check your connection' }),
                        {
                            headers: { 'Content-Type': 'application/json' },
                            status: 503
                        }
                    )
                })
        )
        return
    }

    // Handle navigation requests
    if (request.mode === 'navigate') {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    // Cache successful responses
                    if (response.ok) {
                        const responseClone = response.clone()
                        caches.open(RUNTIME_CACHE).then((cache) => {
                            cache.put(request, responseClone)
                        })
                    }
                    return response
                })
                .catch(() => {
                    // Return cached version or offline page
                    return caches.match(request).then((cached) => {
                        return cached || caches.match('/offline')
                    })
                })
        )
        return
    }

    // Handle other requests - cache first, then network
    event.respondWith(
        caches.match(request)
            .then((cached) => {
                if (cached) {
                    // Return cached version and update in background
                    fetch(request).then((response) => {
                        if (response.ok) {
                            caches.open(RUNTIME_CACHE).then((cache) => {
                                cache.put(request, response)
                            })
                        }
                    }).catch(() => { })
                    return cached
                }

                // Not in cache, fetch from network
                return fetch(request)
                    .then((response) => {
                        // Cache successful responses
                        if (response.ok && request.url.startsWith(self.location.origin)) {
                            const responseClone = response.clone()
                            caches.open(RUNTIME_CACHE).then((cache) => {
                                cache.put(request, responseClone)
                            })
                        }
                        return response
                    })
            })
    )
})

// Handle messages from clients
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting()
    }
})

// Push notification handler (for future use)
self.addEventListener('push', (event) => {
    const options = {
        body: event.data ? event.data.text() : 'New notification from WealthWise',
        icon: '/icons/icon-192x192.png',
        badge: '/icons/icon-72x72.png',
        vibrate: [200, 100, 200],
        tag: 'wealthwise-notification',
        requireInteraction: false
    }

    event.waitUntil(
        self.registration.showNotification('WealthWise', options)
    )
})

// Notification click handler
self.addEventListener('notificationclick', (event) => {
    event.notification.close()
    event.waitUntil(
        clients.openWindow('/')
    )
})
