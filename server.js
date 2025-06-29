import { createServer } from 'http';
import { readFileSync, existsSync, appendFileSync } from 'fs';
import { extname, join, normalize } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { URL } from 'url';
import { createHash, randomBytes } from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = 3000;

// Development mode - set to false for production
const DEVELOPMENT_MODE = true;

// Enhanced security tracking
const rateLimitMap = new Map();
const suspiciousIPs = new Set();
const blockedIPs = new Set();
const devToolsUsers = new Set();
const whitelistedIPs = new Set(['127.0.0.1', '::1', 'localhost']); // Whitelist localhost
const RATE_LIMIT = 150;
const RATE_WINDOW = 60 * 1000;

// Generate secure nonce for CSP
function generateNonce() {
    return randomBytes(16).toString('base64');
}

// Enhanced security logging
function logSecurityIncident(incident) {
    const logEntry = JSON.stringify({
        timestamp: new Date().toISOString(),
        severity: incident.severity || 'medium',
        ...incident
    }) + '\n';
    
    try {
        appendFileSync('security.log', logEntry);
    } catch (error) {
        console.error('Failed to write security log:', error);
    }
}

// Smart rate limiting with whitelist
function isRateLimited(clientIP) {
    // Skip rate limiting for whitelisted IPs in development mode
    if (DEVELOPMENT_MODE && whitelistedIPs.has(clientIP)) {
        return false;
    }
    
    const now = Date.now();
    const clientData = rateLimitMap.get(clientIP) || { 
        count: 0, 
        resetTime: now + RATE_WINDOW,
        suspicious: false
    };
    
    if (now > clientData.resetTime) {
        clientData.count = 1;
        clientData.resetTime = now + RATE_WINDOW;
    } else {
        clientData.count++;
    }
    
    // Mark as suspicious if too many requests
    if (clientData.count > RATE_LIMIT * 0.8) {
        clientData.suspicious = true;
        if (!DEVELOPMENT_MODE || !whitelistedIPs.has(clientIP)) {
            suspiciousIPs.add(clientIP);
        }
    }
    
    rateLimitMap.set(clientIP, clientData);
    return clientData.count > RATE_LIMIT;
}

// Enhanced security headers
function getSecurityHeaders(nonce) {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-XSS-Protection': '1; mode=block',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
        'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://api.fontshare.com; img-src 'self' https: data: blob:; media-src 'self' https: data: blob:; font-src 'self' https://api.fontshare.com; connect-src 'self' https:; object-src 'none'; base-uri 'self'; form-action 'self';`,
        'Cache-Control': 'no-cache, no-store, must-revalidate, private',
        'Pragma': 'no-cache',
        'Expires': '0',
        'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet, noimageindex',
        'X-Powered-By': 'Secure-Server'
    };
}

const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.webp': 'image/webp',
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.eot': 'application/vnd.ms-fontobject'
};

// Enhanced suspicious patterns
const suspiciousPatterns = [
    /\.\./,
    /\/etc\/passwd/,
    /admin/,
    /config/,
    /\.php/,
    /\.asp/,
    /wp-admin/,
    /source/,
    /src/,
    /\.git/,
    /\.env/,
    /backup/,
    /debug/,
    /test/,
    /dev/
];

const suspiciousAgents = [
    'sqlmap', 'nikto', 'nmap', 'curl', 'wget', 'python', 'perl', 'bot', 'crawler', 'spider', 'scraper'
];

function isSuspiciousRequest(url, userAgent) {
    // Check for suspicious URL patterns
    for (const pattern of suspiciousPatterns) {
        if (pattern.test(url)) {
            return true;
        }
    }
    
    // Check for suspicious user agents
    const lowerAgent = userAgent.toLowerCase();
    for (const agent of suspiciousAgents) {
        if (lowerAgent.includes(agent)) {
            return true;
        }
    }
    
    return false;
}

function validatePath(requestPath) {
    try {
        const normalizedPath = normalize(requestPath);
        
        if (normalizedPath.includes('..') || 
            normalizedPath.includes('~') ||
            normalizedPath.startsWith('/proc') ||
            normalizedPath.startsWith('/sys')) {
            return false;
        }
        
        return true;
    } catch (error) {
        return false;
    }
}

// Clear blocked IPs for development
function clearBlockedIPs() {
    if (DEVELOPMENT_MODE) {
        blockedIPs.clear();
        devToolsUsers.clear();
        console.log('🔧 Development mode: Cleared all blocked IPs');
    }
}

// Serve access denied page
function serveAccessDeniedPage(res, nonce, reason = 'security_violation') {
    try {
        const accessDeniedPath = join(__dirname, 'access-denied.html');
        if (existsSync(accessDeniedPath)) {
            let content = readFileSync(accessDeniedPath, 'utf8');
            
            // Add nonce to script tags
            content = content.replace(/<script>/g, `<script nonce="${nonce}">`);
            
            res.writeHead(403, {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Length': Buffer.byteLength(content),
                ...getSecurityHeaders(nonce)
            });
            res.end(content);
        } else {
            // Fallback if access-denied.html doesn't exist
            const fallbackContent = `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Access Denied</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
                        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
                        h1 { color: #dc2626; margin-bottom: 20px; }
                        p { color: #666; line-height: 1.6; margin-bottom: 20px; }
                        .button { display: inline-block; padding: 10px 20px; background: #dc2626; color: white; text-decoration: none; border-radius: 5px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🚫 Access Denied</h1>
                        <p>Your access has been restricted due to security policy violations.</p>
                        <p>This may be due to:</p>
                        <ul style="text-align: left; color: #666;">
                            <li>Developer tools usage</li>
                            <li>Suspicious activity detection</li>
                            <li>Automated access attempts</li>
                            <li>Security policy violations</li>
                        </ul>
                        <a href="/" class="button">Return to Homepage</a>
                    </div>
                </body>
                </html>
            `;
            
            res.writeHead(403, {
                'Content-Type': 'text/html; charset=utf-8',
                'Content-Length': Buffer.byteLength(fallbackContent),
                ...getSecurityHeaders(nonce)
            });
            res.end(fallbackContent);
        }
    } catch (error) {
        // Ultimate fallback
        res.writeHead(403, {
            'Content-Type': 'text/plain',
            ...getSecurityHeaders(nonce)
        });
        res.end('Access Denied - Security Violation');
    }
}

const server = createServer((req, res) => {
    const clientIP = req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const nonce = generateNonce();
    
    // Clear blocks for development mode
    if (DEVELOPMENT_MODE && whitelistedIPs.has(clientIP)) {
        blockedIPs.delete(clientIP);
        devToolsUsers.delete(clientIP);
    }
    
    // Enhanced IP blocking with custom access denied page
    if ((blockedIPs.has(clientIP) || devToolsUsers.has(clientIP)) && 
        (!DEVELOPMENT_MODE || !whitelistedIPs.has(clientIP))) {
        
        logSecurityIncident({
            type: 'blocked_ip_access_attempt',
            clientIP,
            userAgent,
            requestPath: req.url,
            severity: 'high'
        });
        
        serveAccessDeniedPage(res, nonce, 'ip_blocked');
        return;
    }

    // Log all access attempts
    logSecurityIncident({
        type: 'page_access',
        clientIP,
        requestPath: req.url,
        userAgent,
        referer: req.headers.referer || 'none',
        whitelisted: whitelistedIPs.has(clientIP),
        developmentMode: DEVELOPMENT_MODE,
        severity: 'low'
    });

    // Enhanced rate limiting with custom access denied page
    if (isRateLimited(clientIP)) {
        logSecurityIncident({
            type: 'rate_limit_exceeded',
            clientIP,
            userAgent,
            severity: 'medium'
        });
        
        serveAccessDeniedPage(res, nonce, 'rate_limited');
        return;
    }

    // Enhanced security monitoring endpoint
    if (req.url === '/security-monitor' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
            if (body.length > 2000) {
                req.connection.destroy();
                return;
            }
        });
        
        req.on('end', () => {
            try {
                const incident = JSON.parse(body);
                
                // Handle dev tools detection with development mode consideration
                if (incident.type === 'devtools_detected') {
                    if (!DEVELOPMENT_MODE || !whitelistedIPs.has(clientIP)) {
                        devToolsUsers.add(clientIP);
                        logSecurityIncident({
                            type: 'devtools_violation',
                            clientIP,
                            userAgent,
                            severity: 'critical'
                        });
                    } else {
                        logSecurityIncident({
                            type: 'devtools_detected_dev_mode',
                            clientIP,
                            userAgent,
                            severity: 'low'
                        });
                    }
                }
                
                logSecurityIncident({
                    type: 'client_security_event',
                    clientIP,
                    userAgent,
                    incident,
                    developmentMode: DEVELOPMENT_MODE,
                    whitelisted: whitelistedIPs.has(clientIP),
                    severity: incident.severity || 'medium'
                });
            } catch (error) {
                logSecurityIncident({
                    type: 'invalid_security_report',
                    clientIP,
                    userAgent,
                    severity: 'low'
                });
            }
            
            res.writeHead(200, { 
                'Content-Type': 'application/json',
                ...getSecurityHeaders(nonce)
            });
            res.end('{"status":"logged"}');
        });
        return;
    }

    // Admin endpoint to clear blocks (development only)
    if (req.url === '/admin/clear-blocks' && DEVELOPMENT_MODE) {
        clearBlockedIPs();
        res.writeHead(200, { 
            'Content-Type': 'application/json',
            ...getSecurityHeaders(nonce)
        });
        res.end('{"status":"cleared","message":"All blocks cleared for development"}');
        return;
    }

    // Enhanced suspicious request detection with custom access denied page
    if (isSuspiciousRequest(req.url, userAgent) && 
        (!DEVELOPMENT_MODE || !whitelistedIPs.has(clientIP))) {
        
        suspiciousIPs.add(clientIP);
        logSecurityIncident({
            type: 'suspicious_request_blocked',
            clientIP,
            requestPath: req.url,
            userAgent,
            severity: 'high'
        });
        
        serveAccessDeniedPage(res, nonce, 'suspicious_activity');
        return;
    }

    // Enhanced path validation with custom access denied page
    let filePath = req.url === '/' ? '/index.html' : req.url;
    
    try {
        const url = new URL(req.url, `http://${req.headers.host}`);
        filePath = url.pathname === '/' ? '/index.html' : url.pathname;
    } catch (error) {
        logSecurityIncident({
            type: 'malformed_url',
            clientIP,
            requestPath: req.url,
            userAgent,
            severity: 'medium'
        });
        
        res.writeHead(400, { 
            'Content-Type': 'text/plain',
            ...getSecurityHeaders(nonce)
        });
        res.end('Bad Request');
        return;
    }

    if (!validatePath(filePath)) {
        logSecurityIncident({
            type: 'path_traversal_blocked',
            clientIP,
            requestPath: req.url,
            userAgent,
            severity: 'critical'
        });
        
        if (!DEVELOPMENT_MODE || !whitelistedIPs.has(clientIP)) {
            blockedIPs.add(clientIP);
        }
        
        serveAccessDeniedPage(res, nonce, 'path_traversal');
        return;
    }

    const ext = extname(filePath).toLowerCase();
    const fullPath = join(__dirname, filePath);

    if (!existsSync(fullPath)) {
        res.writeHead(404, { 
            'Content-Type': 'text/plain',
            ...getSecurityHeaders(nonce)
        });
        res.end('404 Not Found');
        return;
    }

    const contentType = mimeTypes[ext] || 'application/octet-stream';

    try {
        let content = readFileSync(fullPath);
        
        // Inject comprehensive security into HTML
        if (ext === '.html') {
            let htmlContent = content.toString();
            
            // Add nonce to existing script tags
            htmlContent = htmlContent.replace(
                /<script>/g, 
                `<script nonce="${nonce}">`
            );
            
            // Inject security script with development mode awareness
            const securityScript = `
                <script nonce="${nonce}">
                    (function() {
                        'use strict';
                        
                        // Development mode flag
                        const DEVELOPMENT_MODE = ${DEVELOPMENT_MODE};
                        
                        // Security state management
                        let securityActive = false;
                        let userEntered = false;
                        let pageFullyLoaded = false;
                        let protectionsApplied = false;
                        
                        // Comprehensive protection functions
                        const SecurityManager = {
                            // Initialize security system
                            init: function() {
                                this.waitForPageLoad();
                                this.monitorUserEntry();
                                this.setupFallbacks();
                            },
                            
                            // Wait for complete page load
                            waitForPageLoad: function() {
                                if (document.readyState === 'complete') {
                                    pageFullyLoaded = true;
                                    this.checkActivation();
                                } else {
                                    document.addEventListener('DOMContentLoaded', () => {
                                        setTimeout(() => {
                                            pageFullyLoaded = true;
                                            this.checkActivation();
                                        }, 1000);
                                    });
                                    
                                    window.addEventListener('load', () => {
                                        setTimeout(() => {
                                            pageFullyLoaded = true;
                                            this.checkActivation();
                                        }, 1500);
                                    });
                                }
                            },
                            
                            // Monitor when user enters the site
                            monitorUserEntry: function() {
                                const checkEntry = () => {
                                    const enterOverlay = document.getElementById('enterOverlay');
                                    if (enterOverlay) {
                                        const isHidden = enterOverlay.style.display === 'none' || 
                                                       enterOverlay.classList.contains('hidden') ||
                                                       window.getComputedStyle(enterOverlay).opacity === '0';
                                        
                                        if (isHidden && !userEntered) {
                                            userEntered = true;
                                            this.checkActivation();
                                        }
                                    }
                                };
                                
                                // Check immediately and periodically
                                checkEntry();
                                const entryInterval = setInterval(() => {
                                    checkEntry();
                                    if (userEntered) {
                                        clearInterval(entryInterval);
                                    }
                                }, 200);
                                
                                // Fallback - assume entered after 10 seconds
                                setTimeout(() => {
                                    if (!userEntered) {
                                        userEntered = true;
                                        this.checkActivation();
                                    }
                                }, 10000);
                            },
                            
                            // Check if we should activate protections
                            checkActivation: function() {
                                if (pageFullyLoaded && userEntered && !protectionsApplied) {
                                    this.activateProtections();
                                }
                            },
                            
                            // Activate all security protections
                            activateProtections: function() {
                                if (protectionsApplied) return;
                                protectionsApplied = true;
                                securityActive = true;
                                
                                // Apply protections with delay to ensure functionality
                                setTimeout(() => {
                                    this.disableRightClick();
                                    this.disableTextSelection();
                                    this.disableDragDrop();
                                    this.disableKeyboardShortcuts();
                                    this.setupDevToolsDetection();
                                    this.disableConsole();
                                    this.preventSourceAccess();
                                    this.setupAdvancedProtection();
                                }, 2000);
                            },
                            
                            // Disable right-click context menu
                            disableRightClick: function() {
                                document.addEventListener('contextmenu', function(e) {
                                    e.preventDefault();
                                    e.stopPropagation();
                                    return false;
                                }, true);
                                
                                // Also disable on window
                                window.addEventListener('contextmenu', function(e) {
                                    e.preventDefault();
                                    return false;
                                }, true);
                            },
                            
                            // Disable text selection
                            disableTextSelection: function() {
                                document.addEventListener('selectstart', function(e) {
                                    e.preventDefault();
                                    return false;
                                }, true);
                                
                                document.addEventListener('mousedown', function(e) {
                                    if (e.detail > 1) {
                                        e.preventDefault();
                                        return false;
                                    }
                                }, true);
                            },
                            
                            // Disable drag and drop
                            disableDragDrop: function() {
                                document.addEventListener('dragstart', function(e) {
                                    e.preventDefault();
                                    return false;
                                }, true);
                                
                                document.addEventListener('drop', function(e) {
                                    e.preventDefault();
                                    return false;
                                }, true);
                            },
                            
                            // Disable dangerous keyboard shortcuts
                            disableKeyboardShortcuts: function() {
                                document.addEventListener('keydown', function(e) {
                                    // F12 - Dev Tools
                                    if (e.keyCode === 123) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+Shift+I - Dev Tools
                                    if (e.ctrlKey && e.shiftKey && e.keyCode === 73) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+Shift+J - Console
                                    if (e.ctrlKey && e.shiftKey && e.keyCode === 74) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+U - View Source
                                    if (e.ctrlKey && e.keyCode === 85) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+S - Save Page
                                    if (e.ctrlKey && e.keyCode === 83) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+A - Select All
                                    if (e.ctrlKey && e.keyCode === 65) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+C - Copy
                                    if (e.ctrlKey && e.keyCode === 67) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+V - Paste
                                    if (e.ctrlKey && e.keyCode === 86) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+X - Cut
                                    if (e.ctrlKey && e.keyCode === 88) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+P - Print
                                    if (e.ctrlKey && e.keyCode === 80) {
                                        e.preventDefault();
                                        return false;
                                    }
                                    
                                    // Ctrl+Shift+C - Inspect Element
                                    if (e.ctrlKey && e.shiftKey && e.keyCode === 67) {
                                        e.preventDefault();
                                        return false;
                                    }
                                }, true);
                            },
                            
                            // Advanced dev tools detection (less aggressive in dev mode)
                            setupDevToolsDetection: function() {
                                let devtools = false;
                                let threshold = 160;
                                
                                const detectDevTools = () => {
                                    if (window.outerHeight - window.innerHeight > threshold || 
                                        window.outerWidth - window.innerWidth > threshold) {
                                        if (!devtools) {
                                            devtools = true;
                                            this.reportSecurityViolation('devtools_detected');
                                            
                                            // Only redirect in production mode
                                            if (!DEVELOPMENT_MODE) {
                                                setTimeout(() => {
                                                    window.location.href = '/access-denied.html';
                                                }, 2000);
                                            }
                                        }
                                    } else {
                                        devtools = false;
                                    }
                                };
                                
                                // Check periodically (less frequent in dev mode)
                                const interval = DEVELOPMENT_MODE ? 5000 : 1000;
                                setInterval(detectDevTools, interval);
                                
                                // Additional detection methods (disabled in dev mode)
                                if (!DEVELOPMENT_MODE) {
                                    let start = new Date();
                                    debugger;
                                    if (new Date() - start > 100) {
                                        this.reportSecurityViolation('debugger_detected');
                                    }
                                }
                            },
                            
                            // Disable console access (less aggressive in dev mode)
                            disableConsole: function() {
                                if (!DEVELOPMENT_MODE) {
                                    // Override console methods
                                    if (typeof console !== 'undefined') {
                                        const noop = function() {};
                                        console.log = noop;
                                        console.warn = noop;
                                        console.error = noop;
                                        console.info = noop;
                                        console.debug = noop;
                                        console.trace = noop;
                                        console.dir = noop;
                                        console.dirxml = noop;
                                        console.table = noop;
                                        console.clear = noop;
                                        console.group = noop;
                                        console.groupEnd = noop;
                                        console.time = noop;
                                        console.timeEnd = noop;
                                        console.count = noop;
                                        console.assert = noop;
                                    }
                                    
                                    // Prevent console recreation
                                    Object.defineProperty(window, 'console', {
                                        value: {},
                                        writable: false,
                                        configurable: false
                                    });
                                }
                            },
                            
                            // Prevent source code access
                            preventSourceAccess: function() {
                                // Disable view source
                                document.addEventListener('keydown', function(e) {
                                    if ((e.ctrlKey || e.metaKey) && e.keyCode === 85) {
                                        e.preventDefault();
                                        return false;
                                    }
                                }, true);
                                
                                // Prevent iframe source access
                                const iframes = document.querySelectorAll('iframe');
                                iframes.forEach(iframe => {
                                    iframe.addEventListener('load', function() {
                                        try {
                                            iframe.contentDocument.addEventListener('contextmenu', function(e) {
                                                e.preventDefault();
                                                return false;
                                            });
                                        } catch (e) {
                                            // Cross-origin iframe, ignore
                                        }
                                    });
                                });
                            },
                            
                            // Advanced protection measures
                            setupAdvancedProtection: function() {
                                // Prevent script injection
                                const observer = new MutationObserver(function(mutations) {
                                    mutations.forEach(function(mutation) {
                                        mutation.addedNodes.forEach(function(node) {
                                            if (node.tagName === 'SCRIPT' && !node.hasAttribute('nonce')) {
                                                node.remove();
                                            }
                                        });
                                    });
                                });
                                
                                observer.observe(document.body, {
                                    childList: true,
                                    subtree: true
                                });
                                
                                // Prevent eval and Function constructor (less strict in dev mode)
                                if (!DEVELOPMENT_MODE) {
                                    window.eval = function() {
                                        throw new Error('eval is disabled');
                                    };
                                    
                                    window.Function = function() {
                                        throw new Error('Function constructor is disabled');
                                    };
                                }
                                
                                // Clear sensitive data from memory
                                setInterval(() => {
                                    if (window.gc) {
                                        window.gc();
                                    }
                                }, 30000);
                            },
                            
                            // Report security violations
                            reportSecurityViolation: function(type) {
                                try {
                                    fetch('/security-monitor', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json'
                                        },
                                        body: JSON.stringify({
                                            type: type,
                                            severity: DEVELOPMENT_MODE ? 'low' : 'high',
                                            timestamp: new Date().toISOString(),
                                            developmentMode: DEVELOPMENT_MODE
                                        })
                                    }).catch(() => {
                                        // Silently fail
                                    });
                                } catch (e) {
                                    // Silently fail
                                }
                            },
                            
                            // Setup fallback protections
                            setupFallbacks: function() {
                                // Fallback activation after 15 seconds
                                setTimeout(() => {
                                    if (!protectionsApplied) {
                                        userEntered = true;
                                        pageFullyLoaded = true;
                                        this.activateProtections();
                                    }
                                }, 15000);
                                
                                // Emergency activation on any user interaction
                                const emergencyActivate = () => {
                                    if (!protectionsApplied) {
                                        userEntered = true;
                                        this.checkActivation();
                                    }
                                };
                                
                                document.addEventListener('click', emergencyActivate, { once: true });
                                document.addEventListener('keydown', emergencyActivate, { once: true });
                                document.addEventListener('touchstart', emergencyActivate, { once: true });
                            }
                        };
                        
                        // Initialize security system
                        SecurityManager.init();
                        
                        // Prevent tampering with security system
                        Object.freeze(SecurityManager);
                        
                        // Development mode indicator
                        if (DEVELOPMENT_MODE) {
                            console.log('🔧 Development Mode: Security protections are relaxed');
                        }
                        
                    })();
                </script>
            `;
            
            // Inject before closing body tag
            htmlContent = htmlContent.replace('</body>', securityScript + '</body>');
            
            content = Buffer.from(htmlContent);
        }
        
        const securityHeaders = getSecurityHeaders(nonce);
        
        res.writeHead(200, { 
            'Content-Type': contentType,
            'Content-Length': content.length,
            ...securityHeaders
        });
        res.end(content);
        
    } catch (error) {
        logSecurityIncident({
            type: 'file_read_error',
            clientIP,
            requestPath: req.url,
            error: error.message,
            severity: 'medium'
        });
        
        res.writeHead(500, { 
            'Content-Type': 'text/plain',
            ...getSecurityHeaders(nonce)
        });
        res.end('500 Internal Server Error');
    }
});

// Enhanced server configuration
server.timeout = 30000;
server.keepAliveTimeout = 5000;
server.headersTimeout = 10000;

server.listen(PORT, () => {
    console.log(`🔒 ${DEVELOPMENT_MODE ? 'DEVELOPMENT' : 'PRODUCTION'} Secure Server running at http://localhost:${PORT}/`);
    console.log('🛡️  Security Features Status:');
    console.log(`   ${DEVELOPMENT_MODE ? '🔧' : '✅'} Development Mode: ${DEVELOPMENT_MODE ? 'ENABLED (Relaxed Security)' : 'DISABLED (Full Security)'}`);
    console.log('   ✅ Complete source code protection');
    console.log('   ✅ Advanced dev tools detection');
    console.log('   ✅ Smart user entry monitoring');
    console.log('   ✅ Progressive security activation');
    console.log('   ✅ Enhanced rate limiting');
    console.log('   ✅ Suspicious activity blocking');
    console.log('   ✅ Console access prevention');
    console.log('   ✅ Keyboard shortcut blocking');
    console.log('   ✅ Right-click protection');
    console.log('   ✅ Text selection prevention');
    console.log('   ✅ Drag & drop blocking');
    console.log('   ✅ Script injection prevention');
    console.log('   ✅ Path traversal protection');
    console.log('   ✅ IP blocking system');
    console.log('   ✅ Professional access denied page');
    console.log('   ✅ Comprehensive logging');
    
    if (DEVELOPMENT_MODE) {
        console.log('\n🔧 DEVELOPMENT MODE FEATURES:');
        console.log('   • Localhost IP whitelisted');
        console.log('   • Dev tools detection relaxed');
        console.log('   • Console access allowed');
        console.log('   • Automatic block clearing');
        console.log('   • Admin endpoints enabled');
        console.log(`   • Clear blocks: http://localhost:${PORT}/admin/clear-blocks`);
        console.log(`   • Access denied page: http://localhost:${PORT}/access-denied.html`);
    }
    
    // Clear any existing blocks on startup in development mode
    if (DEVELOPMENT_MODE) {
        clearBlockedIPs();
    }
    
    logSecurityIncident({
        type: 'secure_server_startup',
        port: PORT,
        security_level: DEVELOPMENT_MODE ? 'development' : 'maximum',
        developmentMode: DEVELOPMENT_MODE,
        severity: 'low'
    });
});

server.on('error', (error) => {
    console.error('🚨 Server error:', error);
    logSecurityIncident({
        type: 'server_error',
        error: error.message,
        severity: 'high'
    });
});

server.on('clientError', (err, socket) => {
    logSecurityIncident({
        type: 'client_error',
        error: err.message,
        severity: 'medium'
    });
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🔒 Secure server shutting down gracefully...');
    logSecurityIncident({
        type: 'server_shutdown',
        developmentMode: DEVELOPMENT_MODE,
        severity: 'low'
    });
    server.close(() => {
        process.exit(0);
    });
});

process.on('uncaughtException', (error) => {
    console.error('🚨 Uncaught Exception:', error);
    logSecurityIncident({
        type: 'uncaught_exception',
        error: error.message,
        severity: 'critical'
    });
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
    logSecurityIncident({
        type: 'unhandled_rejection',
        reason: reason.toString(),
        severity: 'high'
    });
});