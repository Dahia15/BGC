// Configuration - Node.js Proxy Version
const CONFIG = {
    API_BASE: '/api/challonge',
    REDIRECT_URI: 'http://localhost:3000',
    AUTH_URL: 'https://api.challonge.com/oauth/authorize',
    TOKEN_URL: '/api/oauth/token',
    DEVICE_AUTH_URL: '/api/oauth/device',
    DEVICE_TOKEN_URL: '/api/oauth/device/token'
};

// Required scopes for the application
const REQUIRED_SCOPES = 'me tournaments:read tournaments:write matches:read matches:write participants:read participants:write';

// State Management
const state = {
    accessToken: localStorage.getItem('challonge_access_token'),
    refreshToken: localStorage.getItem('challonge_refresh_token'),
    currentUser: null,
    tournaments: [],
    isDemoMode: false,
    currentSection: 'dashboard',
    oauthState: localStorage.getItem('oauth_state') || generateRandomString(16),
    useApiKey: localStorage.getItem('use_api_key') === 'true',
    apiKey: localStorage.getItem('challonge_api_key') || '',
    deviceGrant: {
        deviceCode: null,
        userCode: null,
        verificationUri: null,
        interval: 2000,
        expiresIn: 300
    }
};

// DOM Elements
const elements = {
    loginScreen: document.getElementById('loginScreen'),
    appContainer: document.getElementById('appContainer'),
    logoutBtn: document.getElementById('logoutBtn'),
    userName: document.getElementById('userName'),
    navBtns: document.querySelectorAll('.nav-btn'),
    activeTournaments: document.getElementById('activeTournaments'),
    totalPlayers: document.getElementById('totalPlayers'),
    liveMatches: document.getElementById('liveMatches'),
    completedEvents: document.getElementById('completedEvents'),
    recentTournaments: document.getElementById('recentTournaments'),
    tournamentsTable: document.getElementById('tournamentsTable'),
    createTournamentBtn: document.getElementById('createTournamentBtn'),
    tournamentSelect: document.getElementById('tournamentSelect'),
    liveMatchesList: document.getElementById('liveMatchesList'),
    upcomingMatchesList: document.getElementById('upcomingMatchesList'),
    playerTournamentSelect: document.getElementById('playerTournamentSelect'),
    playersTable: document.getElementById('playersTable'),
    addPlayerBtn: document.getElementById('addPlayerBtn'),
    tournamentModal: document.getElementById('tournamentModal'),
    playerModal: document.getElementById('playerModal'),
    loadingOverlay: document.getElementById('loadingOverlay')
};

// Initialize Application
async function init() {
    console.log('Initializing TournamentPro with redirect URI:', CONFIG.REDIRECT_URI);
    console.log('Using Node.js Proxy System');
    
    await debugOAuthConfiguration();
    testCurrentSetup();
    bindEvents();
    checkOAuthCallback();
    checkAuth();
}

// Debug OAuth configuration
async function debugOAuthConfiguration() {
    console.log('=== OAuth Configuration Debug ===');
    console.log('Redirect URI:', CONFIG.REDIRECT_URI);
    console.log('Required Scopes:', REQUIRED_SCOPES);
    
    try {
        const healthResponse = await fetch('/health');
        const healthData = await healthResponse.json();
        console.log('Server Health:', healthData);
    } catch (error) {
        console.error('Server health check failed:', error);
    }
    
    try {
        const debugResponse = await fetch('/api/oauth/debug');
        const debugData = await debugResponse.json();
        console.log('OAuth Debug:', debugData);
    } catch (error) {
        console.error('OAuth debug failed:', error);
    }
}

// Test current setup
async function testCurrentSetup() {
    console.log('=== Testing Current Setup ===');
    console.log('Current Domain:', window.location.origin);
    console.log('Redirect URI:', CONFIG.REDIRECT_URI);
    console.log('Has Access Token:', !!state.accessToken);
    console.log('Using API Key:', state.useApiKey);
    
    if (state.accessToken || state.useApiKey) {
        console.log('Testing Node.js proxy with current credentials...');
        await testProxyConnection();
    } else {
        console.log('No credentials found - authentication required');
    }
}

// Event Binding
function bindEvents() {
    elements.logoutBtn.addEventListener('click', logout);
    
    elements.navBtns.forEach(btn => {
        btn.addEventListener('click', (e) => switchSection(e.currentTarget.dataset.section));
    });
    
    elements.createTournamentBtn.addEventListener('click', showTournamentModal);
    elements.tournamentSelect.addEventListener('change', loadMatches);
    elements.playerTournamentSelect.addEventListener('change', loadPlayers);
    elements.addPlayerBtn.addEventListener('click', showPlayerModal);
    
    document.getElementById('tournamentForm').addEventListener('submit', createTournament);
    document.getElementById('playerForm').addEventListener('submit', addPlayer);
}

// OAuth2 Functions - FIXED
function checkOAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const error = urlParams.get('error');
    const stateParam = urlParams.get('state');
    
    if (error) {
        showNotification(`OAuth Error: ${error}`, 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
        return;
    }
    
    if (stateParam && stateParam !== state.oauthState) {
        showNotification('Security error: State parameter mismatch', 'error');
        window.history.replaceState({}, document.title, window.location.pathname);
        return;
    }
    
    if (code) {
        console.log('OAuth callback received, exchanging code for token...');
        exchangeCodeForToken(code);
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

function startOAuthFlow() {
    console.log('Starting OAuth flow...');
    
    // Store state for security validation
    const oauthState = generateRandomString(16);
    localStorage.setItem('oauth_state', oauthState);
    state.oauthState = oauthState;
    
    // Use the actual client ID in the authorization request
    const authUrl = new URL(CONFIG.AUTH_URL);
    authUrl.searchParams.append('client_id', '517f81ea42f53ae7978c65643700e8fc874be21804ac91f73807f9b3ebe5d599');
    authUrl.searchParams.append('redirect_uri', CONFIG.REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('state', oauthState);
    authUrl.searchParams.append('scope', REQUIRED_SCOPES);
    
    console.log('OAuth Authorization URL:', authUrl.toString());
    
    window.location.href = authUrl.toString();
}

async function exchangeCodeForToken(code) {
    showLoading();
    
    try {
        console.log('Exchanging authorization code for access token...');
        
        const tokenData = {
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: CONFIG.REDIRECT_URI
        };

        console.log('Token exchange request to Node.js proxy');
        console.log('Code length:', code.length);
        
        const response = await fetch(CONFIG.TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(tokenData)
        });
        
        console.log('Token exchange response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Token exchange failed with response:', errorText);
            throw new Error(`Token exchange failed: ${response.status}`);
        }
        
        const tokenResponse = await response.json();
        console.log('Token exchange successful');
        
        if (!tokenResponse.access_token) {
            throw new Error('No access token received');
        }
        
        state.accessToken = tokenResponse.access_token;
        state.refreshToken = tokenResponse.refresh_token;
        state.useApiKey = false;
        
        localStorage.setItem('challonge_access_token', tokenResponse.access_token);
        if (tokenResponse.refresh_token) {
            localStorage.setItem('challonge_refresh_token', tokenResponse.refresh_token);
        }
        
        console.log('Token stored, verifying...');
        await verifyAccessToken();
        
    } catch (error) {
        console.error('Token exchange failed:', error);
        showNotification('Failed to authenticate: ' + error.message, 'error');
        showLoginScreen();
    } finally {
        hideLoading();
    }
}

async function refreshAccessToken() {
    if (!state.refreshToken) {
        throw new Error('No refresh token available');
    }
    
    try {
        const response = await fetch(CONFIG.TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                refresh_token: state.refreshToken,
                grant_type: 'refresh_token'
            })
        });
        
        if (!response.ok) {
            throw new Error(`Token refresh failed: ${response.status}`);
        }
        
        const tokenData = await response.json();
        
        // Update tokens
        state.accessToken = tokenData.access_token;
        localStorage.setItem('challonge_access_token', tokenData.access_token);
        
        if (tokenData.refresh_token) {
            state.refreshToken = tokenData.refresh_token;
            localStorage.setItem('challonge_refresh_token', tokenData.refresh_token);
        }
        
        console.log('Access token refreshed successfully');
        return true;
        
    } catch (error) {
        console.error('Token refresh failed:', error);
        return false;
    }
}

// API Key Authentication
function useApiKeyAuth(apiKey) {
    state.useApiKey = true;
    state.apiKey = apiKey;
    state.accessToken = null;
    state.refreshToken = null;
    
    localStorage.setItem('use_api_key', 'true');
    localStorage.setItem('challonge_api_key', apiKey);
    localStorage.removeItem('challonge_access_token');
    localStorage.removeItem('challonge_refresh_token');
    
    console.log('Using API key authentication');
    verifyAccessToken();
}

// Authentication Functions
function checkAuth() {
    console.log('Checking authentication...');
    
    if (state.accessToken || state.useApiKey) {
        console.log('Credentials found, verifying...');
        verifyAccessToken();
    } else {
        console.log('No credentials found, showing login screen');
        showLoginScreen();
    }
}

async function verifyAccessToken() {
    showLoading();
    
    try {
        console.log('Verifying credentials...');
        
        try {
            const response = await apiCall('/tournaments.json?page=1&per_page=1');
            console.log('API test successful');
            
            // Fetch actual user information
            try {
                const userResponse = await apiCall('/me');
                state.currentUser = userResponse;
                const username = userResponse.data?.attributes?.username || 
                                userResponse.data?.attributes?.name || 
                                (state.useApiKey ? 'API Key User' : 'OAuth User');
                elements.userName.textContent = username;
                console.log('User info loaded:', username);
            } catch (userError) {
                console.log('Could not fetch user info, using fallback:', userError.message);
                // Fallback if /me endpoint fails
                if (state.useApiKey) {
                    state.currentUser = { 
                        data: { 
                            attributes: { 
                                username: 'API Key User',
                                email: 'api@challonge.com'
                            } 
                        } 
                    };
                    elements.userName.textContent = 'API Key User';
                } else {
                    state.currentUser = { 
                        data: { 
                            attributes: { 
                                username: 'OAuth User',
                                email: 'user@challonge.com'
                            } 
                        } 
                    };
                    elements.userName.textContent = 'OAuth User';
                }
            }
            
        } catch (error) {
            console.log('API test failed:', error.message);
            state.currentUser = { 
                data: { 
                    attributes: { 
                        username: 'Challonge User',
                        email: 'user@challonge.com'
                    } 
                } 
            };
            elements.userName.textContent = 'Challonge User';
            
            throw error;
        }
        
        console.log('Credentials verified successfully');
        state.isDemoMode = false;
        showApp();
        showNotification('Successfully connected to Challonge!', 'success');
        
    } catch (error) {
        console.error('Credential verification failed:', error);
        
        const useDemo = confirm('API Connection Issue: ' + error.message + '\n\nWould you like to use Demo Mode to explore the features?');
        if (useDemo) {
            enableDemoMode();
            return;
        }
        
        showNotification('Authentication failed: ' + error.message, 'error');
        showLoginScreen();
    } finally {
        hideLoading();
    }
}

function showLoginScreen() {
    elements.loginScreen.innerHTML = `
        <div class="login-container">
            <div class="login-card">
                <div class="login-header">
                    <div class="logo">
                        <i class="fas fa-trophy"></i>
                        <span>TournamentPro</span>
                    </div>
                    <h1>Professional Tournament Management</h1>
                    <p>Connect to your Challonge account</p>
                </div>

                <div style="background: #dbeafe; border: 1px solid #3b82f6; border-radius: 8px; padding: 1rem; margin: 1rem 0;">
                    <h4 style="color: #1e40af; margin: 0 0 0.5rem 0;">
                        <i class="fas fa-server"></i> Challonge v2.1 API
                    </h4>
                    <p style="color: #1e40af; margin: 0; font-size: 0.9rem;">
                        This app supports OAuth and API Key authentication. Use the method that fits your workflow.
                    </p>
                </div>

                <div class="login-actions" style="display:flex; gap:0.5rem; flex-wrap:wrap;">
                    <button id="oauthConnectBtn" class="btn btn-primary btn-large" style="flex:1; min-width:200px;">
                        <i class="fas fa-sign-in-alt"></i>
                        Sign in with Challonge
                    </button>
                    <button id="apiKeyBtn" class="btn btn-outline btn-large" style="flex:1; min-width:200px;">
                        <i class="fas fa-key"></i>
                        Use API Key
                    </button>
                    <button id="demoBtn" class="btn btn-ghost btn-large" style="flex-basis:100%; margin-top:0.5rem;">
                        <i class="fas fa-play-circle"></i>
                        Try Demo Mode
                    </button>
                </div>

                <div class="connection-info" style="margin-top:1rem;">
                    <p><strong>Using Challonge API v2.1</strong></p>
                    <p style="font-size:0.95rem; margin:0.25rem 0;">Required scopes: ${REQUIRED_SCOPES}</p>
                    <p style="margin-top: 1rem; font-size: 0.9rem;">
                        <a href="/api/test-challonge" target="_blank">Test API Connection</a> |
                        <a href="/health" target="_blank">Server Status</a>
                    </p>
                </div>
            </div>
        </div>
    `;

    // attach handlers (keep existing functionality)
    const oauthBtn = document.getElementById('oauthConnectBtn');
    if (oauthBtn) oauthBtn.addEventListener('click', startOAuthFlow);

    const apiBtn = document.getElementById('apiKeyBtn');
    if (apiBtn) apiBtn.addEventListener('click', showApiKeyModal);

    const demoBtn = document.getElementById('demoBtn');
    if (demoBtn) demoBtn.addEventListener('click', enableDemoMode);

    elements.loginScreen.classList.remove('hidden');
    elements.appContainer.classList.add('hidden');
}

function showApiKeyModal() {
    const modalHtml = `
        <div class="modal" id="apiKeyModal">
            <div class="modal-backdrop"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Enter API Key</h3>
                    <button class="modal-close" onclick="hideApiKeyModal()">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label class="form-label">Challonge API Key</label>
                        <input type="password" id="apiKeyInput" class="form-input" required 
                               placeholder="Enter your API key from challonge.com/settings/developer">
                        <div class="form-help">
                            Get your API key from: <a href="https://challonge.com/settings/developer" target="_blank">challonge.com/settings/developer</a>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline" onclick="hideApiKeyModal()">Cancel</button>
                    <button type="button" class="btn btn-primary" onclick="submitApiKey()">Connect</button>
                </div>
            </div>
        </div>
    `;
    
    const existingModal = document.getElementById('apiKeyModal');
    if (existingModal) {
        existingModal.remove();
    }
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    document.getElementById('apiKeyModal').classList.remove('hidden');
    document.getElementById('apiKeyInput').focus();
}

function hideApiKeyModal() {
    const modal = document.getElementById('apiKeyModal');
    if (modal) {
        modal.remove();
    }
}

function submitApiKey() {
    const apiKey = document.getElementById('apiKeyInput').value.trim();
    if (!apiKey) {
        showNotification('Please enter an API key', 'error');
        return;
    }
    
    hideApiKeyModal();
    useApiKeyAuth(apiKey);
}

function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function showApp() {
    elements.loginScreen.classList.add('hidden');
    elements.appContainer.classList.remove('hidden');
    loadDashboardData();
}

function enableDemoMode() {
    state.isDemoMode = true;
    state.currentUser = { data: { attributes: { username: 'Demo User' } } };
    elements.userName.textContent = 'Demo User';
    showApp();
    loadDemoData();
    showNotification('Demo mode activated. Explore features with sample data.', 'info');
}

function logout() {
    state.accessToken = null;
    state.refreshToken = null;
    state.currentUser = null;
    state.isDemoMode = false;
    state.tournaments = [];
    state.useApiKey = false;
    state.apiKey = '';
    state.deviceGrant = {
        deviceCode: null,
        userCode: null,
        verificationUri: null,
        interval: 2000,
        expiresIn: 300
    };
    
    localStorage.removeItem('challonge_access_token');
    localStorage.removeItem('challonge_refresh_token');
    localStorage.removeItem('challonge_api_key');
    localStorage.removeItem('use_api_key');
    localStorage.removeItem('oauth_state');
    
    showLoginScreen();
    showNotification('Successfully signed out.', 'info');
}

// API Functions with Node.js Proxy
async function apiCall(endpoint, options = {}) {
    if (state.isDemoMode) {
        return new Promise(resolve => setTimeout(() => {
            if (endpoint.includes('/tournaments/') && endpoint.includes('/participants')) {
                resolve({ data: getDemoPlayers() });
            } else if (endpoint.includes('/tournaments/') && endpoint.includes('/matches')) {
                resolve({ data: getDemoMatches() });
            } else if (endpoint.includes('/tournaments.json')) {
                resolve({ data: getDemoTournaments() });
            } else if (endpoint.includes('/me.json')) {
                resolve({ data: { attributes: { username: 'Demo User' } } });
            } else {
                resolve({ data: [] });
            }
        }, 800));
    }
    
    try {
        const url = CONFIG.API_BASE + endpoint;
        
        const defaultOptions = {
            headers: {
                'Content-Type': 'application/vnd.api+json',
                'Accept': 'application/json'
            }
        };
        
        if (state.useApiKey && state.apiKey) {
            defaultOptions.headers['Authorization'] = state.apiKey;
            defaultOptions.headers['Authorization-Type'] = 'v1';
        } else if (state.accessToken) {
            defaultOptions.headers['Authorization'] = `Bearer ${state.accessToken}`;
        }

        const finalOptions = { ...defaultOptions, ...options };
        
        console.log('Making API call to Node.js proxy:', url);
        if (finalOptions.body) {
            console.log('Request body preview:', finalOptions.body.substring(0, 200));
        }
        
        const response = await fetch(url, finalOptions);
        
        if (!response.ok) {
            let errorText = await response.text();
            console.error('API error response:', errorText);
            
            try {
                const errorJson = JSON.parse(errorText);
                errorText = errorJson.errors ? JSON.stringify(errorJson.errors) : errorText;
            } catch (e) {
                // Not JSON, use as-is
            }
            
            if (response.status === 401) {
                if (!state.useApiKey) {
                    const refreshed = await refreshAccessToken();
                    if (refreshed) {
                        return apiCall(endpoint, options);
                    }
                }
                throw new Error('Unauthorized - Invalid credentials');
            } else if (response.status === 403) {
                throw new Error('Forbidden - Insufficient permissions');
            } else if (response.status === 404) {
                if (endpoint.includes('/me.json')) {
                    return { 
                        data: { 
                            type: 'user',
                            attributes: {
                                username: 'Challonge User',
                                email: 'user@challonge.com'
                            }
                        } 
                    };
                }
                if (endpoint.includes('/tournaments.json')) {
                    return { data: [] };
                }
                throw new Error('Not Found - Endpoint does not exist');
            } else if (response.status === 500) {
                throw new Error('Server Error - Challonge API returned an error');
            } else {
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
        }
        
        const data = await response.json();
        console.log('API call successful via Node.js proxy');
        return data;
        
    } catch (error) {
        console.error('API call failed:', error);
        
        if (error.message.includes('Failed to fetch')) {
            throw new Error('Node.js proxy server is not running. Please start the server with "npm start"');
        }
        
        if (error.message.includes('Unauthorized') && endpoint.includes('/tournaments.json')) {
            console.log('Authentication issue - returning empty tournaments array');
            return { data: [] };
        }
        
        throw error;
    }
}

async function createTournamentApi(tournamentPayload) {
    // Use JSON:API format required by Challonge v2.1
    const payload = {
        data: {
            type: 'tournaments',
            attributes: tournamentPayload
        }
    };
    console.log('Sending tournament payload:', JSON.stringify(payload));
    return apiCall('/tournaments.json', { method: 'POST', body: JSON.stringify(payload) });
}

// Debug function to test Node.js proxy connection
async function testProxyConnection() {
    console.log('=== Testing Node.js Proxy Connection ===');
    
    if (!state.accessToken && !state.useApiKey) {
        console.log('No credentials available for testing');
        return -1;
    }
    
    try {
        console.log('Testing Node.js proxy connection...');
        const response = await apiCall('/tournaments.json?page=1&per_page=1');
        console.log('✅ Node.js Proxy SUCCESS - API is responding');
        return 0;
        
    } catch (error) {
        console.log('❌ Node.js Proxy FAILED -', error.message);
        return -1;
    }
}

// Demo Data Functions
function getDemoTournaments() {
    return [
        {
            id: 'demo-1',
            type: 'tournament',
            attributes: {
                name: 'Weekend Championship',
                game_name: 'Street Fighter 6',
                tournament_type: 'single elimination',
                participants_count: 16,
                state: 'underway',
                description: 'Weekly competitive tournament',
                url: 'weekend_championship_demo',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        },
        {
            id: 'demo-2',
            type: 'tournament',
            attributes: {
                name: 'Pro League Qualifiers',
                game_name: 'Valorant',
                tournament_type: 'double elimination',
                participants_count: 32,
                state: 'pending',
                description: 'Qualification event',
                url: 'pro_league_qualifiers_demo',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        },
        {
            id: 'demo-3',
            type: 'tournament',
            attributes: {
                name: 'Community Cup',
                game_name: 'Rocket League',
                tournament_type: 'round robin',
                participants_count: 8,
                state: 'complete',
                description: 'Monthly community event',
                url: 'community_cup_demo',
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString()
            }
        }
    ];
}

function getDemoPlayers() {
    return [
        {
            id: 'demo-player-1',
            type: 'participant',
            attributes: {
                name: 'ProPlayer1',
                seed: 1,
                final_rank: null,
                misc: '',
                username: 'proplayer1'
            }
        },
        {
            id: 'demo-player-2',
            type: 'participant',
            attributes: {
                name: 'GamerGirl92',
                seed: 2,
                final_rank: null,
                misc: '',
                username: 'gamergirl92'
            }
        },
        {
            id: 'demo-player-3',
            type: 'participant',
            attributes: {
                name: 'TournamentKing',
                seed: 3,
                final_rank: null,
                misc: '',
                username: 'tournamentking'
            }
        }
    ];
}

function getDemoMatches() {
    return [
        {
            id: 'demo-match-1',
            type: 'match',
            attributes: {
                state: 'open',
                round: 1,
                identifier: 'A',
                suggested_play_order: 1,
                scores: '0-0',
                winner_id: null
            }
        },
        {
            id: 'demo-match-2',
            type: 'match',
            attributes: {
                state: 'pending',
                round: 1,
                identifier: 'B',
                suggested_play_order: 2,
                scores: '',
                winner_id: null
            }
        }
    ];
}

function loadDemoData() {
    console.log('Loading demo data...');
    state.tournaments = getDemoTournaments();
    
    updateDashboardStats();
    displayRecentTournaments();
    displayTournamentsTable();
    populateTournamentSelects();
    
    console.log('Demo data loaded:', state.tournaments.length, 'tournaments');
}

// Navigation
function switchSection(sectionName) {
    elements.navBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.section === sectionName);
    });
    
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.toggle('active', section.id === sectionName);
    });
    
    state.currentSection = sectionName;
    
    switch(sectionName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'tournaments':
            loadTournaments();
            break;
        case 'matches':
            loadMatches();
            break;
        case 'players':
            loadPlayers();
            break;
        case 'analytics':
            loadAnalytics();
            break;
    }
}

// Dashboard Functions
async function loadDashboardData() {
    showLoading();
    
    try {
        if (state.isDemoMode) {
            loadDemoData();
        } else {
            try {
                const tournaments = await apiCall('/tournaments.json?page=1&per_page=50');
                state.tournaments = tournaments.data || [];
                console.log('Loaded tournaments:', state.tournaments.length);
            } catch (error) {
                console.log('Failed to load real tournaments, using demo data:', error.message);
                state.tournaments = getDemoTournaments();
                showNotification('Using demo data due to API error', 'warning');
            }
            
            updateDashboardStats();
            displayRecentTournaments();
            populateTournamentSelects();
        }
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
        showNotification('Failed to load dashboard data: ' + error.message, 'error');
        state.tournaments = [];
        updateDashboardStats();
        displayRecentTournaments();
    } finally {
        hideLoading();
    }
}

function updateDashboardStats() {
    const activeTournaments = state.tournaments.filter(t => 
        t.attributes && ['pending', 'underway'].includes(t.attributes.state)
    ).length;
    
    elements.activeTournaments.textContent = activeTournaments;
    elements.liveMatches.textContent = state.isDemoMode ? '2' : '0';
    elements.completedEvents.textContent = state.tournaments.filter(t => 
        t.attributes && t.attributes.state === 'complete'
    ).length;
    
    elements.totalPlayers.textContent = state.tournaments.reduce((total, t) => 
        total + (t.attributes?.participants_count || 0), 0
    );
}

function displayRecentTournaments() {
    const recent = state.tournaments.slice(0, 5);
    
    if (recent.length === 0) {
        elements.recentTournaments.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-chess"></i>
                <p>No tournaments found</p>
                ${!state.isDemoMode ? '<p style="font-size: 0.875rem; margin-top: 0.5rem; color: var(--secondary);">Create your first tournament to get started!</p>' : ''}
            </div>
        `;
        return;
    }
    
    elements.recentTournaments.innerHTML = recent.map(tournament => `
        <div class="tournament-item" style="padding: 1rem; border-bottom: 1px solid var(--border);">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h4 style="margin: 0 0 0.25rem 0; color: var(--dark);">${tournament.attributes.name}</h4>
                    <p style="margin: 0; color: var(--secondary); font-size: 0.875rem;">
                        ${tournament.attributes.game_name || 'No game'} • 
                        ${formatTournamentType(tournament.attributes.tournament_type)}
                    </p>
                </div>
                <span class="status-badge ${getStatusClass(tournament.attributes.state)}">
                    ${formatTournamentState(tournament.attributes.state)}
                </span>
            </div>
        </div>
    `).join('');
}

// Tournament Functions
async function loadTournaments() {
    showLoading();
    
    try {
        if (state.isDemoMode) {
            state.tournaments = getDemoTournaments();
        } else {
            try {
                const response = await apiCall('/tournaments.json?page=1&per_page=50');
                state.tournaments = response.data || [];
            } catch (error) {
                console.log('Failed to load real tournaments:', error.message);
                state.tournaments = getDemoTournaments();
                showNotification('Using demo data due to API error', 'warning');
            }
        }
        displayTournamentsTable();
        
    } catch (error) {
        console.error('Failed to load tournaments:', error);
        showNotification('Failed to load tournaments: ' + error.message, 'error');
        state.tournaments = [];
        displayTournamentsTable();
    } finally {
        hideLoading();
    }
}

function displayTournamentsTable() {
    if (state.tournaments.length === 0) {
        elements.tournamentsTable.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    <i class="fas fa-chess"></i>
                    <p>No tournaments found</p>
                </td>
            </tr>
        `;
        return;
    }
    
    elements.tournamentsTable.innerHTML = state.tournaments.map(tournament => `
        <tr>
            <td>
                <div style="font-weight: 500; color: var(--dark);">${tournament.attributes.name}</div>
                <div style="font-size: 0.875rem; color: var(--secondary);">
                    ${tournament.attributes.description || 'No description'}
                </div>
            </td>
            <td>${tournament.attributes.game_name || '-'}</td>
            <td>${formatTournamentType(tournament.attributes.tournament_type)}</td>
            <td>${tournament.attributes.participants_count || 0}</td>
            <td>
                <span class="status-badge ${getStatusClass(tournament.attributes.state)}">
                    ${formatTournamentState(tournament.attributes.state)}
                </span>
            </td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-outline" onclick="viewTournament('${tournament.id}')">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-outline" onclick="editTournament('${tournament.id}')">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

function populateTournamentSelects() {
    const options = state.tournaments.map(t => 
        `<option value="${t.id}">${t.attributes.name}</option>`
    ).join('');
    
    const selectHTML = '<option value="">Select Tournament</option>' + options;
    
    elements.tournamentSelect.innerHTML = selectHTML;
    elements.playerTournamentSelect.innerHTML = selectHTML;
}

// Modal Functions
function showTournamentModal() {
    elements.tournamentModal.classList.remove('hidden');
}

function hideTournamentModal() {
    elements.tournamentModal.classList.add('hidden');
    document.getElementById('tournamentForm').reset();
}

async function createTournament(e) {
    e.preventDefault();
    showLoading();
    
    const formName = document.getElementById('tournamentName').value.trim();
    const formGame = document.getElementById('tournamentGame').value.trim();
    const formType = document.getElementById('tournamentType').value;
    const formMaxParticipants = document.getElementById('maxParticipants')?.value.trim();
    
    const payload = {
        name: formName || `Tournament ${new Date().toLocaleString()}`,
        game_name: formGame || '',
        tournament_type: formType || 'single elimination',
        url: generateTournamentUrl(formName),
        description: `Tournament for ${formGame || 'untitled'}`,
        max_participants: formMaxParticipants ? parseInt(formMaxParticipants) : null
    };
    
    try {
        if (state.isDemoMode) {
            const newTournament = {
                id: 'demo-new-' + Date.now(),
                type: 'tournament',
                attributes: {
                    ...payload,
                    participants_count: 0,
                    state: 'pending',
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                }
            };
            state.tournaments.unshift(newTournament);
            showNotification('Tournament created successfully! (Demo Mode)', 'success');
        } else {
            // Call the real API
            await createTournamentApi(payload);
            showNotification('Tournament created successfully!', 'success');
        }
        
        hideTournamentModal();
        await loadTournaments();
        
        // Also update dashboard if we're on that section
        if (state.currentSection === 'dashboard') {
            updateDashboardStats();
            displayRecentTournaments();
            populateTournamentSelects();
        }
        
    } catch (error) {
        console.error('Failed to create tournament:', error);
        showNotification('Failed to create tournament: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function showPlayerModal() {
    if (!elements.playerTournamentSelect.value) {
        showNotification('Please select a tournament first', 'warning');
        return;
    }
    elements.playerModal.classList.remove('hidden');
}

function hidePlayerModal() {
    elements.playerModal.classList.add('hidden');
    document.getElementById('playerForm').reset();
}

async function addPlayer(e) {
    e.preventDefault();
    showLoading();
    
    const playerName = document.getElementById('playerName').value;
    
    try {
        if (state.isDemoMode) {
            showNotification('Player added successfully! (Demo Mode)', 'success');
        } else {
            showNotification('Player addition would be sent to Challonge API in production', 'info');
        }
        
        hidePlayerModal();
        
    } catch (error) {
        console.error('Failed to add player:', error);
        showNotification('Failed to add player: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

// Player Functions
async function loadPlayers() {
    const tournamentId = elements.playerTournamentSelect.value;
    if (!tournamentId) {
        elements.playersTable.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    <i class="fas fa-users"></i>
                    <p>Select a tournament to view players</p>
                </td>
            </tr>
        `;
        return;
    }
    
    showLoading();
    
    try {
        if (state.isDemoMode) {
            displayPlayersTable(getDemoPlayers());
        } else {
            try {
                const response = await apiCall(`/tournaments/${tournamentId}/participants`);
                const participants = response.data || [];
                displayPlayersTable(participants);
            } catch (error) {
                console.log('Failed to load participants:', error.message);
                elements.playersTable.innerHTML = `
                    <tr>
                        <td colspan="6" class="empty-state">
                            <i class="fas fa-exclamation-circle"></i>
                            <p>Failed to load participants</p>
                            <p style="font-size: 0.875rem; color: var(--secondary);">${error.message}</p>
                        </td>
                    </tr>
                `;
            }
        }
        
    } catch (error) {
        console.error('Failed to load players:', error);
        showNotification('Failed to load players: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function displayPlayersTable(players) {
    const tournamentId = elements.playerTournamentSelect.value;
    
    if (players.length === 0) {
        elements.playersTable.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    <i class="fas fa-users"></i>
                    <p>No players in this tournament</p>
                </td>
            </tr>
        `;
        return;
    }
    
    elements.playersTable.innerHTML = players.map(player => `
        <tr>
            <td>
                <div style="font-weight: 500; color: var(--dark);">${player.attributes.name}</div>
                <div style="font-size: 0.875rem; color: var(--secondary);">
                    ${player.attributes.username || 'No username'}
                </div>
            </td>
            <td>${player.attributes.seed || '-'}</td>
            <td>-</td>
            <td>-</td>
            <td>
                <span class="status-badge success">Active</span>
            </td>
            <td>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="btn btn-sm btn-outline" onclick="editPlayer('${player.id}', '${tournamentId}')">
                        <i class="fas fa-edit"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

// Match Functions
async function loadMatches() {
    const tournamentId = elements.tournamentSelect.value;
    if (!tournamentId) return;
    
    showLoading();
    
    try {
        if (state.isDemoMode) {
            displayMatches(getDemoMatches());
        } else {
            try {
                const response = await apiCall(`/tournaments/${tournamentId}/matches`);
                const matches = response.data || [];
                displayMatches(matches);
            } catch (error) {
                console.log('Failed to load matches:', error.message);
                elements.liveMatchesList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-exclamation-circle"></i>
                        <p>Failed to load matches</p>
                        <p style="font-size: 0.875rem; color: var(--secondary);">${error.message}</p>
                    </div>
                `;
                elements.upcomingMatchesList.innerHTML = '';
            }
        }
        
    } catch (error) {
        console.error('Failed to load matches:', error);
        showNotification('Failed to load matches: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function displayMatches(matches) {
    const tournamentId = elements.tournamentSelect.value;
    const liveMatches = matches.filter(m => m.attributes.state === 'open');
    const upcomingMatches = matches.filter(m => m.attributes.state === 'pending');
    
    if (liveMatches.length === 0) {
        elements.liveMatchesList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-gamepad"></i>
                <p>No live matches</p>
            </div>
        `;
    } else {
        elements.liveMatchesList.innerHTML = liveMatches.map(match => `
            <div class="match-item" style="padding: 1rem; border-bottom: 1px solid var(--border);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <h4 style="margin: 0 0 0.25rem 0; color: var(--dark);">
                            Match ${match.attributes.identifier || match.attributes.round}
                        </h4>
                        <p style="margin: 0; color: var(--secondary); font-size: 0.875rem;">
                            Round ${match.attributes.round}
                        </p>
                    </div>
                    <button class="btn btn-sm btn-primary" onclick="reportScore('${match.id}', '${tournamentId}')">
                        Report Score
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    if (upcomingMatches.length === 0) {
        elements.upcomingMatchesList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-clock"></i>
                <p>No upcoming matches</p>
            </div>
        `;
    } else {
        elements.upcomingMatchesList.innerHTML = upcomingMatches.map(match => `
            <div class="match-item" style="padding: 1rem; border-bottom: 1px solid var(--border);">
                <div>
                    <h4 style="margin: 0 0 0.25rem 0; color: var(--dark);">
                        Match ${match.attributes.identifier || match.attributes.round}
                    </h4>
                    <p style="margin: 0; color: var(--secondary); font-size: 0.875rem;">
                        Round ${match.attributes.round} • Waiting to start
                    </p>
                </div>
            </div>
        `).join('');
    }
}

// Analytics Functions
function loadAnalytics() {
    console.log('Loading analytics...');
}

// Utility Functions
function formatTournamentType(type) {
    const types = {
        'single elimination': 'Single Elimination',
        'double elimination': 'Double Elimination', 
        'round robin': 'Round Robin',
        'swiss': 'Swiss System'
    };
    return types[type] || type;
}

function formatTournamentState(state) {
    const states = {
        'pending': 'Pending',
        'underway': 'In Progress',
        'awaiting_review': 'Awaiting Review',
        'complete': 'Completed'
    };
    return states[state] || state;
}

function getStatusClass(state) {
    const classes = {
        'pending': 'warning',
        'underway': 'primary',
        'complete': 'success',
        'awaiting_review': 'secondary'
    };
    return classes[state] || 'secondary';
}

function generateTournamentUrl(name) {
    return name.toLowerCase()
        .replace(/[^a-z0-9]/g, '_')
        .replace(/_+/g, '_')
        .substring(0, 50) + '_' + Date.now();
}

function showLoading() {
    elements.loadingOverlay.classList.remove('hidden');
}

function hideLoading() {
    elements.loadingOverlay.classList.add('hidden');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 12px 20px;
        border-radius: var(--radius);
        color: white;
        font-weight: 500;
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };
    
    notification.style.background = colors[type] || colors.info;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// Tournament View/Edit Functions
async function viewTournament(tournamentId) {
    const modal = document.getElementById('viewTournamentModal');
    const content = document.getElementById('tournamentDetailsContent');
    
    modal.classList.remove('hidden');
    content.innerHTML = '<div class="loading-spinner"><div class="spinner"></div></div>';
    
    try {
        const response = await apiCall(`/tournaments/${tournamentId}`);
        const tournament = response.data;
        
        // Fetch participants
        let participants = [];
        try {
            const participantsResponse = await apiCall(`/tournaments/${tournamentId}/participants`);
            participants = participantsResponse.data || [];
        } catch (err) {
            console.log('Could not load participants:', err);
        }
        
        // Fetch matches
        let matches = [];
        try {
            const matchesResponse = await apiCall(`/tournaments/${tournamentId}/matches`);
            matches = matchesResponse.data || [];
        } catch (err) {
            console.log('Could not load matches:', err);
        }
        
        const attrs = tournament.attributes;
        content.innerHTML = `
            <div style="display: grid; gap: 1.5rem;">
                <div>
                    <h2 style="margin: 0 0 0.5rem 0; color: var(--dark);">${attrs.name}</h2>
                    <p style="margin: 0; color: var(--secondary);">${attrs.description || 'No description'}</p>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem;">
                    <div class="stat-card">
                        <div class="stat-content">
                            <p style="color: var(--secondary); font-size: 0.875rem; margin: 0;">Game</p>
                            <h4 style="margin: 0.25rem 0 0 0; color: var(--dark);">${attrs.game_name || 'Not specified'}</h4>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-content">
                            <p style="color: var(--secondary); font-size: 0.875rem; margin: 0;">Type</p>
                            <h4 style="margin: 0.25rem 0 0 0; color: var(--dark);">${formatTournamentType(attrs.tournament_type)}</h4>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-content">
                            <p style="color: var(--secondary); font-size: 0.875rem; margin: 0;">Status</p>
                            <h4 style="margin: 0.25rem 0 0 0;">
                                <span class="status-badge ${getStatusClass(attrs.state)}">
                                    ${formatTournamentState(attrs.state)}
                                </span>
                            </h4>
                        </div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-content">
                            <p style="color: var(--secondary); font-size: 0.875rem; margin: 0;">Participants</p>
                            <h4 style="margin: 0.25rem 0 0 0; color: var(--dark);">${attrs.participants_count || 0}</h4>
                        </div>
                    </div>
                </div>
                
                ${participants.length > 0 ? `
                    <div>
                        <h3 style="margin: 0 0 1rem 0; color: var(--dark);">Participants</h3>
                        <div style="display: grid; gap: 0.5rem;">
                            ${participants.slice(0, 10).map(p => `
                                <div style="padding: 0.75rem; background: var(--background); border-radius: var(--border-radius); display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-weight: 500;">${p.attributes.name}</span>
                                    <span style="color: var(--secondary); font-size: 0.875rem;">Seed: ${p.attributes.seed || 'N/A'}</span>
                                </div>
                            `).join('')}
                            ${participants.length > 10 ? `<p style="text-align: center; color: var(--secondary); margin: 0.5rem 0 0 0;">... and ${participants.length - 10} more</p>` : ''}
                        </div>
                    </div>
                ` : '<p style="color: var(--secondary);">No participants yet</p>'}
                
                ${matches.length > 0 ? `
                    <div>
                        <h3 style="margin: 0 0 1rem 0; color: var(--dark);">Recent Matches</h3>
                        <div style="display: grid; gap: 0.5rem;">
                            ${matches.slice(0, 5).map(m => `
                                <div style="padding: 0.75rem; background: var(--background); border-radius: var(--border-radius);">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <span style="font-weight: 500;">Round ${m.attributes.round}</span>
                                        <span class="status-badge ${getStatusClass(m.attributes.state)}">
                                            ${m.attributes.state}
                                        </span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
                
                <div style="padding: 1rem; background: var(--background); border-radius: var(--border-radius);">
                    <p style="margin: 0; color: var(--secondary); font-size: 0.875rem;">
                        <strong>URL:</strong> ${attrs.url || 'N/A'}<br>
                        <strong>Created:</strong> ${attrs.created_at ? new Date(attrs.created_at).toLocaleDateString() : 'N/A'}
                    </p>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Failed to load tournament:', error);
        content.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-circle"></i>
                <p>Failed to load tournament details</p>
                <p style="font-size: 0.875rem; color: var(--secondary);">${error.message}</p>
            </div>
        `;
    }
}

function hideViewTournamentModal() {
    document.getElementById('viewTournamentModal').classList.add('hidden');
}

async function editTournament(tournamentId) {
    const modal = document.getElementById('editTournamentModal');
    modal.classList.remove('hidden');
    
    try {
        // Load tournament data
        const response = await apiCall(`/tournaments/${tournamentId}`);
        const tournament = response.data;
        const attrs = tournament.attributes;
        
        // Populate form
        document.getElementById('editTournamentId').value = tournamentId;
        document.getElementById('editTournamentName').value = attrs.name || '';
        document.getElementById('editTournamentGame').value = attrs.game_name || '';
        document.getElementById('editTournamentDescription').value = attrs.description || '';
        
        // Handle form submission
        const form = document.getElementById('editTournamentForm');
        form.onsubmit = async (e) => {
            e.preventDefault();
            await submitTournamentEdit();
        };
    } catch (error) {
        console.error('Failed to load tournament for editing:', error);
        showNotification('Failed to load tournament: ' + error.message, 'error');
        hideEditTournamentModal();
    }
}

async function submitTournamentEdit() {
    showLoading();
    
    const tournamentId = document.getElementById('editTournamentId').value;
    const name = document.getElementById('editTournamentName').value.trim();
    const game_name = document.getElementById('editTournamentGame').value.trim();
    const description = document.getElementById('editTournamentDescription').value.trim();
    
    try {
        const payload = {
            data: {
                type: 'tournaments',
                attributes: {
                    name,
                    game_name,
                    description
                }
            }
        };
        
        await apiCall(`/tournaments/${tournamentId}`, {
            method: 'PUT',
            body: JSON.stringify(payload)
        });
        
        showNotification('Tournament updated successfully!', 'success');
        hideEditTournamentModal();
        await loadTournaments();
        
        if (state.currentSection === 'dashboard') {
            updateDashboardStats();
            displayRecentTournaments();
        }
    } catch (error) {
        console.error('Failed to update tournament:', error);
        showNotification('Failed to update tournament: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function hideEditTournamentModal() {
    document.getElementById('editTournamentModal').classList.add('hidden');
}

async function editPlayer(playerId, tournamentId) {
    // Need tournament ID to update participant
    if (!tournamentId) {
        // Try to get from current tournament selection
        tournamentId = document.getElementById('tournamentSelect')?.value;
        if (!tournamentId) {
            showNotification('Please select a tournament first', 'warning');
            return;
        }
    }
    
    const modal = document.getElementById('editPlayerModal');
    modal.classList.remove('hidden');
    
    try {
        // Load participant data
        const response = await apiCall(`/tournaments/${tournamentId}/participants/${playerId}`);
        const participant = response.data;
        const attrs = participant.attributes;
        
        // Populate form
        document.getElementById('editPlayerId').value = playerId;
        document.getElementById('editPlayerTournamentId').value = tournamentId;
        document.getElementById('editPlayerName').value = attrs.name || '';
        document.getElementById('editPlayerSeed').value = attrs.seed || '';
        
        // Handle form submission
        const form = document.getElementById('editPlayerForm');
        form.onsubmit = async (e) => {
            e.preventDefault();
            await submitPlayerEdit();
        };
    } catch (error) {
        console.error('Failed to load participant for editing:', error);
        showNotification('Failed to load participant: ' + error.message, 'error');
        hideEditPlayerModal();
    }
}

async function submitPlayerEdit() {
    showLoading();
    
    const playerId = document.getElementById('editPlayerId').value;
    const tournamentId = document.getElementById('editPlayerTournamentId').value;
    const name = document.getElementById('editPlayerName').value.trim();
    const seed = document.getElementById('editPlayerSeed').value;
    
    try {
        const payload = {
            data: {
                type: 'participants',
                attributes: {
                    name,
                    ...(seed && { seed: parseInt(seed) })
                }
            }
        };
        
        await apiCall(`/tournaments/${tournamentId}/participants/${playerId}`, {
            method: 'PUT',
            body: JSON.stringify(payload)
        });
        
        showNotification('Participant updated successfully!', 'success');
        hideEditPlayerModal();
        await loadPlayers();
    } catch (error) {
        console.error('Failed to update participant:', error);
        showNotification('Failed to update participant: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function hideEditPlayerModal() {
    document.getElementById('editPlayerModal').classList.add('hidden');
}

async function reportScore(matchId, tournamentId) {
    // Need tournament ID to update match
    if (!tournamentId) {
        tournamentId = document.getElementById('tournamentSelect')?.value;
        if (!tournamentId) {
            showNotification('Please select a tournament first', 'warning');
            return;
        }
    }
    
    const modal = document.getElementById('reportScoreModal');
    modal.classList.remove('hidden');
    
    const participantsDiv = document.getElementById('matchParticipants');
    const winnerSelect = document.getElementById('reportScoreWinner');
    
    try {
        // Load match data
        const response = await apiCall(`/tournaments/${tournamentId}/matches/${matchId}`);
        const match = response.data;
        const attrs = match.attributes;
        
        // Get participant names
        const player1Id = attrs.player1_id;
        const player2Id = attrs.player2_id;
        
        let player1Name = 'Player 1';
        let player2Name = 'Player 2';
        
        if (player1Id) {
            try {
                const p1 = await apiCall(`/tournaments/${tournamentId}/participants/${player1Id}`);
                player1Name = p1.data.attributes.name;
            } catch (err) {
                console.log('Could not load player 1 name');
            }
        }
        
        if (player2Id) {
            try {
                const p2 = await apiCall(`/tournaments/${tournamentId}/participants/${player2Id}`);
                player2Name = p2.data.attributes.name;
            } catch (err) {
                console.log('Could not load player 2 name');
            }
        }
        
        // Update UI
        participantsDiv.innerHTML = `
            <div style="padding: 1rem; background: var(--background); border-radius: var(--border-radius);">
                <p style="margin: 0 0 0.5rem 0; color: var(--secondary); font-size: 0.875rem;">Match Details</p>
                <div style="display: flex; justify-content: space-between; align-items: center; font-weight: 500;">
                    <span>${player1Name}</span>
                    <span style="color: var(--secondary);">vs</span>
                    <span>${player2Name}</span>
                </div>
            </div>
        `;
        
        winnerSelect.innerHTML = `
            <option value="">Select winner</option>
            ${player1Id ? `<option value="${player1Id}">${player1Name}</option>` : ''}
            ${player2Id ? `<option value="${player2Id}">${player2Name}</option>` : ''}
        `;
        
        // Store IDs in form
        document.getElementById('reportScoreMatchId').value = matchId;
        document.getElementById('reportScoreTournamentId').value = tournamentId;
        
        // Handle form submission
        const form = document.getElementById('reportScoreForm');
        form.onsubmit = async (e) => {
            e.preventDefault();
            await submitMatchScore();
        };
    } catch (error) {
        console.error('Failed to load match details:', error);
        showNotification('Failed to load match: ' + error.message, 'error');
        hideReportScoreModal();
    }
}

async function submitMatchScore() {
    showLoading();
    
    const matchId = document.getElementById('reportScoreMatchId').value;
    const tournamentId = document.getElementById('reportScoreTournamentId').value;
    const winnerId = document.getElementById('reportScoreWinner').value;
    const scores = document.getElementById('reportScoreValue').value.trim();
    
    if (!winnerId) {
        showNotification('Please select a winner', 'warning');
        hideLoading();
        return;
    }
    
    try {
        const payload = {
            data: {
                type: 'matches',
                attributes: {
                    winner_id: winnerId,
                    ...(scores && { scores_csv: scores })
                }
            }
        };
        
        await apiCall(`/tournaments/${tournamentId}/matches/${matchId}`, {
            method: 'PUT',
            body: JSON.stringify(payload)
        });
        
        showNotification('Match score reported successfully!', 'success');
        hideReportScoreModal();
        await loadMatches();
    } catch (error) {
        console.error('Failed to report score:', error);
        showNotification('Failed to report score: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

function hideReportScoreModal() {
    document.getElementById('reportScoreModal').classList.add('hidden');
}

// Initialize the application
document.addEventListener('DOMContentLoaded', init);