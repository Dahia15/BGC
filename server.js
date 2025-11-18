import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors());
// Parse both application/json and application/vnd.api+json
app.use(express.json({ type: ['application/json', 'application/vnd.api+json'] }));
app.use(express.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main HTML file for all routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Add this helper function at the top of the file after imports
async function fetchWithRetry(url, options, maxRetries = 3) {
    let lastError = null;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            console.log(`[Attempt ${attempt}/${maxRetries}] Fetching: ${url}`);
            const response = await fetch(url, options);
            const responseText = await response.text();
            
            console.log(`[Attempt ${attempt}] Response status: ${response.status}`);
            
            // Check for Cloudflare challenge or HTML error pages
            const isHtml = responseText.trim().startsWith('<') || 
                          responseText.includes('<!DOCTYPE') || 
                          responseText.includes('<html');
            
            if (isHtml && (responseText.includes('Just a moment') || 
                          responseText.includes('Checking your browser') ||
                          responseText.includes('cloudflare'))) {
                console.log(`[Attempt ${attempt}] Cloudflare challenge detected, waiting before retry...`);
                
                if (attempt < maxRetries) {
                    // Exponential backoff with jitter: 2^attempt * 1000ms + random jitter
                    const baseDelay = Math.min(Math.pow(2, attempt) * 1000, 10000);
                    const jitter = Math.random() * 1000;
                    const delay = baseDelay + jitter;
                    console.log(`[Attempt ${attempt}] Waiting ${Math.round(delay)}ms before retry...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    continue;
                }
            }
            
            // If response is OK or it's a valid error response (JSON), return it
            if (response.ok || !isHtml) {
                console.log(`[Attempt ${attempt}] Request successful or valid response received`);
                return { response, responseText };
            }
            
            // If we got HTML but not Cloudflare, treat as error
            if (isHtml) {
                console.log(`[Attempt ${attempt}] Received HTML error page`);
                lastError = new Error(`Received HTML error page (status ${response.status})`);
                
                if (attempt < maxRetries) {
                    const delay = Math.min(Math.pow(2, attempt) * 1000, 10000);
                    console.log(`[Attempt ${attempt}] Retrying in ${delay}ms...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    continue;
                }
            }
            
            return { response, responseText };
            
        } catch (error) {
            console.error(`[Attempt ${attempt}] Fetch error:`, error.message);
            lastError = error;
            
            if (attempt < maxRetries) {
                const delay = Math.min(Math.pow(2, attempt) * 1000, 10000);
                console.log(`[Attempt ${attempt}] Network error, retrying in ${delay}ms...`);
                await new Promise(resolve => setTimeout(resolve, delay));
                continue;
            }
        }
    }
    
    console.error(`All ${maxRetries} attempts failed`);
    throw lastError || new Error('Max retries exceeded');
}

// OAuth Debug Endpoint
app.get('/api/oauth/debug', (req, res) => {
    res.json({
        client_id: process.env.CLIENT_ID ? '***' + process.env.CLIENT_ID.slice(-8) : 'Not configured',
        redirect_uri: process.env.REDIRECT_URI || 'Not configured',
        required_scopes: getRequiredScopes(),
        has_client_secret: !!process.env.CLIENT_SECRET,
        has_api_key: !!process.env.CHALLONGE_API_KEY,
        server_health: 'OK'
    });
});

// OAuth Token Exchange Endpoint
app.post('/api/oauth/token', async (req, res) => {
    try {
        console.log('OAuth token exchange request received (server-side only)');
        const { code, grant_type, redirect_uri, refresh_token } = req.body;

        // Only accept server-side credentials - do not trust client-sent client_id/client_secret
        if (!grant_type || (grant_type === 'authorization_code' && !code) || (grant_type === 'refresh_token' && !refresh_token)) {
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'Missing required fields for grant_type'
            });
        }

        // If a REDIRECT_URI is set in server env, validate the incoming redirect_uri matches it
        if (process.env.REDIRECT_URI && redirect_uri && redirect_uri !== process.env.REDIRECT_URI) {
            console.warn('Redirect URI mismatch', { provided: redirect_uri, expected: process.env.REDIRECT_URI });
            return res.status(400).json({
                error: 'invalid_request',
                error_description: 'redirect_uri does not match server configuration'
            });
        }

        const tokenUrl = 'https://challonge.com/oauth/token';
        const formData = new URLSearchParams();
        
        // Validate credentials are available
        if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
            console.error('OAuth credentials not configured!');
            return res.status(500).json({
                error: 'server_configuration_error',
                error_description: 'OAuth CLIENT_ID or CLIENT_SECRET not configured on server. Please check .env file.'
            });
        }
        
        formData.append('client_id', process.env.CLIENT_ID);
        formData.append('client_secret', process.env.CLIENT_SECRET);
        formData.append('grant_type', grant_type);

        if (grant_type === 'authorization_code') {
            formData.append('code', code);
            if (redirect_uri) formData.append('redirect_uri', redirect_uri);
        } else if (grant_type === 'refresh_token') {
            formData.append('refresh_token', refresh_token);
        }

        console.log('Exchanging token with Challonge (server-side).');
        console.log('Token URL:', tokenUrl);
        console.log('Grant type:', grant_type);

        const fetchOptions = {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/x-www-form-urlencoded', 
                'Accept': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Origin': process.env.REDIRECT_URI || 'http://localhost:3000',
                'Referer': 'https://challonge.com/'
            },
            body: formData,
            redirect: 'follow'
        };

        const { response, responseText } = await fetchWithRetry(tokenUrl, fetchOptions, 5);
        console.log('Token exchange response received, status:', response.status);
        console.log('Response text preview:', responseText.substring(0, 200));
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error('Failed to parse Challonge token response:', parseError);
            console.error('Full response text:', responseText);
            return res.status(502).json({ 
                error: 'invalid_response', 
                error_description: 'Invalid JSON from Challonge', 
                debug: responseText.substring(0, 500) 
            });
        }

        if (!response.ok) {
            return res.status(response.status).json(data);
        }

        // Log and enforce scopes
        const granted = parseScopes(data.scope || data.scopes || '');
        const required = getRequiredScopes();
        console.log('Token granted scopes:', granted);
        const missing = required.filter(s => !granted.includes(s));
        if (missing.length) {
            console.warn('Token missing required scopes - rejecting exchange', { missing });
            return res.status(403).json({
                error: 'insufficient_scopes',
                error_description: 'Token missing required scopes',
                granted: granted,
                missing
            });
        }

        // Return token response to client (access_token, refresh_token, expires_in, etc.)
        console.log('Token exchange successful, returning tokens to client');
        res.json(data);
    } catch (error) {
        console.error('Token exchange error:', error);
        console.error('Error stack:', error.stack);
        res.status(500).json({ 
            error: 'server_error', 
            error_description: error.message,
            details: error.stack?.split('\n')[0] || 'No additional details'
        });
    }
});

// API Proxy Endpoint - FIXED body consumption issue
app.all('/api/challonge/*', async (req, res) => {
    try {
        let challongePath = req.path.replace('/api/challonge', '');
        // Normalize legacy .json suffixes so both "/tournaments.json" and "/tournaments" work
        if (challongePath.endsWith('.json')) {
            challongePath = challongePath.replace(/\.json$/, '');
        }
        
        // Use the correct API v2.1 base URL
        const baseUrl = 'https://api.challonge.com/v2.1';
        const url = `${baseUrl}${challongePath}`;
        
        console.log('Proxying request to:', url);
        console.log('Method:', req.method);
        console.log('Request body:', JSON.stringify(req.body, null, 2));
        
        // Build headers by forwarding most client headers to Challonge,
        // but filter out hop-by-hop and host headers that should not be forwarded.
        // Start by copying incoming headers, omitting hop-by-hop and host headers.
        const hopByHop = new Set([
            'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
            'te', 'trailers', 'transfer-encoding', 'upgrade'
        ]);
        
        const headers = {};
        Object.entries(req.headers).forEach(([k, v]) => {
            const key = k.toLowerCase();
            if (hopByHop.has(key)) return;
            // Keep Authorization, Authorization-Type, Content-Type, Accept, etc.
            headers[key] = v;
        });
        
        // Ensure required Accept/Content-Type defaults for Challonge v2.1
        headers['accept'] = headers['accept'] || 'application/json';
        headers['content-type'] = headers['content-type'] || 'application/vnd.api+json';
        
        // Authorization handling:
        // - Prefer the client's Authorization header (OAuth access token).
        // - If you want a server-side API key fallback, set CHALLONGE_API_KEY in .env (NOT CLIENT_ID).
        // - If neither exists, return 401 with a helpful message.
        if (headers['authorization']) {
            console.log('Forwarding Authorization header from client:', headers['authorization'].slice(0, 20) + '...');
        } else if (process.env.CHALLONGE_API_KEY) {
            headers['authorization'] = `Bearer ${process.env.CHALLONGE_API_KEY}`;
            console.log('Using CHALLONGE_API_KEY from env as Bearer token (fallback)');
        } else {
            console.log('No Authorization provided and no CHALLONGE_API_KEY set — rejecting request');
            return res.status(401).json({
                error: 'Missing credentials',
                message: 'Provide an Authorization: Bearer <access_token> header from the client, or set CHALLONGE_API_KEY in .env for server-side fallback.'
            });
        }

        const fetchOptions = {
            method: req.method,
            headers: headers
        };

        // Add body for non-GET requests
        if (req.method !== 'GET' && req.body) {
            fetchOptions.body = JSON.stringify(req.body);
            console.log('Request body being sent to Challonge:', fetchOptions.body);
        }

        console.log('Request headers:', headers);
        const response = await fetch(url, fetchOptions);
        
        console.log('Challonge API response status:', response.status);
        
        // Read the response once and store it
        const responseText = await response.text();
        let data;
        
        try {
            data = JSON.parse(responseText);
            console.log('Successfully parsed JSON response');
        } catch (jsonError) {
            console.error('JSON parse error:', jsonError);
            console.error('Response text (first 500 chars):', responseText.substring(0, 500));
            
            if (response.status === 401) {
                data = { 
                    error: 'Authentication failed',
                    message: 'Invalid API key or token. Please check your Challonge credentials.',
                    status: 401,
                    data: [] // Return empty array for consistency
                };
            } else if (response.status === 404) {
                data = { 
                    error: 'Endpoint not found',
                    message: `The API endpoint ${challongePath} was not found.`,
                    status: 404,
                    data: [] // Return empty array for consistency
                };
            } else {
                data = { 
                    error: 'API request failed',
                    status: response.status,
                    message: `Received status ${response.status} from Challonge API`,
                    data: [] // Return empty array for consistency
                };
            }
        }
        
        res.status(response.status).json(data);
        
    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({ 
            error: 'Proxy server error',
            message: error.message,
            data: [] // Return empty array for consistency
        });
    }
});

// Test endpoint for Challonge v2.1 API - FIXED body consumption
app.get('/api/test-challonge', async (req, res) => {
    try {
        const url = 'https://api.challonge.com/v2.1/tournaments';
        
        console.log('Testing Challonge v2.1 API with URL:', url);
        
        // Use incoming Authorization header if present, otherwise use CHALLONGE_API_KEY if set.
        const headers = {
            'Content-Type': 'application/vnd.api+json',
            'Accept': 'application/json'
        };

        if (req.headers.authorization) {
            headers['Authorization'] = req.headers.authorization;
            console.log('Using Authorization header from request');
        } else if (process.env.CHALLONGE_API_KEY) {
            headers['Authorization'] = `Bearer ${process.env.CHALLONGE_API_KEY}`;
            console.log('Using CHALLONGE_API_KEY from env for test');
        } else {
            return res.status(400).json({
                error: 'No credentials available',
                message: 'Provide Authorization header or set CHALLONGE_API_KEY in .env to run this test.'
            });
        }

        console.log('Request headers preview:', { authorization: headers['Authorization'].slice(0, 20) + '...' });
        const response = await fetch(url, { headers });
        
        // Read response once and store it
        const responseText = await response.text();
        
        const result = {
            url: url,
            status: response.status,
            statusText: response.statusText,
            ok: response.ok
        };
        
        if (response.ok) {
            try {
                const data = JSON.parse(responseText);
                result.data = data;
                result.message = `Success! Found ${data.data ? data.data.length : 'data'} tournaments`;
            } catch (e) {
                result.jsonError = e.message;
                result.rawResponse = responseText.substring(0, 500);
            }
        } else {
            result.error = responseText;
        }
        
        res.json({
            test_time: new Date().toISOString(),
            client_id: process.env.CLIENT_ID ? '***' + process.env.CLIENT_ID.slice(-8) : 'not set',
            result
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'TournamentPro server is running',
        timestamp: new Date().toISOString(),
        api_version: 'v2.1'
    });
});

// Helper: normalize scope string -> array
function parseScopes(scopeValue) {
    if (!scopeValue) return [];
    if (Array.isArray(scopeValue)) return scopeValue.map(s => s.trim());
    return scopeValue.split(/\s+|,/).map(s => s.trim()).filter(Boolean);
}

// Helper: get required scopes from env or default
function getRequiredScopes() {
    const raw = process.env.REQUIRED_SCOPES || 'me';
    return parseScopes(raw);
}

// New endpoint: validate scopes (accepts { tokenResponse } or { scope })
app.post('/api/oauth/validate-scopes', (req, res) => {
    try {
        const tokenResponse = req.body.tokenResponse || {};
        const scopeFromBody = req.body.scope;
        const scopeValue = tokenResponse.scope || scopeFromBody || '';
        const grantedScopes = parseScopes(scopeValue);
        const requiredScopes = getRequiredScopes();

        console.log('OAuth scope validation request');
        console.log('Granted scopes:', grantedScopes);
        console.log('Required scopes:', requiredScopes);

        const missing = requiredScopes.filter(s => !grantedScopes.includes(s));
        if (missing.length > 0) {
            return res.status(403).json({
                error: 'insufficient_scopes',
                message: 'Token is missing required scopes',
                granted: grantedScopes,
                missing
            });
        }

        return res.json({
            ok: true,
            granted: grantedScopes
        });

    } catch (err) {
        console.error('Scope validation error:', err);
        return res.status(500).json({ error: 'server_error', message: err.message });
    }
});

// Device Grant: request device code and poll for token

// POST /api/oauth/device
// Request a device_code / user_code / verification_uri from Challonge
app.post('/api/oauth/device', async (req, res) => {
    try {
        const clientId = process.env.CLIENT_ID;
        if (!clientId) return res.status(500).json({ error: 'server_error', error_description: 'Missing CLIENT_ID on server' });

        const deviceUrl = 'https://challonge.com/oauth/device_authorization'; // Challonge device endpoint (adjust if necessary)
        const body = new URLSearchParams({ client_id: clientId });

        const fetchOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json',
                'User-Agent': 'Node.js Device Grant'
            },
            body
        };

        const { response, responseText } = await fetchWithRetry(deviceUrl, fetchOptions);
        let data;
        try { data = JSON.parse(responseText); } catch (err) {
            return res.status(502).json({ error: 'invalid_response', error_description: 'Non-JSON from Challonge', debug: responseText.substring(0,200) });
        }

        return res.status(response.status).json(data);
    } catch (err) {
        console.error('Device request error:', err);
        return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
});

// POST /api/oauth/device/token
// Poll token endpoint with device_code -> returns token when user authorizes
app.post('/api/oauth/device/token', async (req, res) => {
    try {
        const { device_code } = req.body;
        if (!device_code) return res.status(400).json({ error: 'invalid_request', error_description: 'device_code required' });

        if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET) {
            return res.status(500).json({ error: 'server_error', error_description: 'Missing CLIENT_ID/CLIENT_SECRET on server' });
        }

        const tokenUrl = 'https://challonge.com/oauth/token';
        // Use standard device grant grant_type (RFC) — some providers accept 'device_code' instead. Adjust if necessary.
        const formData = new URLSearchParams({
            client_id: process.env.CLIENT_ID,
            client_secret: process.env.CLIENT_SECRET,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code
        });

        const fetchOptions = {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
            body: formData
        };

        const { response, responseText } = await fetchWithRetry(tokenUrl, fetchOptions);
        let data;
        try { data = JSON.parse(responseText); } catch (err) {
            return res.status(502).json({ error: 'invalid_response', error_description: 'Non-JSON from Challonge', debug: responseText.substring(0,200) });
        }

        // Pass through Challonge response (may include error like 'authorization_pending' or the access_token)
        return res.status(response.status).json(data);

    } catch (err) {
        console.error('Device token poll error:', err);
        return res.status(500).json({ error: 'server_error', error_description: err.message });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 TournamentPro Server running on http://localhost:${PORT}`);
    console.log('📁 Serving files from:', path.join(__dirname, 'public'));
    console.log('🔑 OAuth endpoint: /api/oauth/token');
    console.log('🌐 API proxy: /api/challonge/*');
    console.log('🧪 Test endpoint: /api/test-challonge');
    console.log('❤️  Health check: /health');
    console.log('🔧 Using Challonge v2.1 API with Bearer token authentication');
    console.log('🔑 API Key:', process.env.CLIENT_ID ? '***' + process.env.CLIENT_ID.slice(-8) : 'Not set');
});