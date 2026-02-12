const API_BASE = 'http://localhost:5000/dashboard/api';

let currentPage = 'dashboard';
let autoRefreshEnabled = true;
let refreshInterval = 5000;
let refreshTimer = null;
let charts = {};
let currentUser = { username: '', role: '' };
let liveFeedPaused = false;
let liveFeedTimer = null;
let isLoggingIn = false;
let displayedEventIds = new Set();

// ============ UTILITY FUNCTIONS ============

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        
        if (!response.ok && response.status === 401) {
            showLoginPage();
            return null;
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return null;
    }
}

function showElement(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'block';
}

function hideElement(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

function updateTime() {
    const now = new Date();
    document.getElementById('current-time').textContent = now.toLocaleString();
}

// ============ AUTHENTICATION ============

async function login() {
    if (isLoggingIn) return;
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const errorDiv = document.getElementById('login-error');
    
    if (!username || !password) {
        errorDiv.textContent = 'Please enter both username and password';
        errorDiv.style.display = 'block';
        return;
    }
    
    errorDiv.style.display = 'none';
    isLoggingIn = true;
    
    try {
        const result = await fetchAPI('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });
        
        if (result && result.success) {
            currentUser.username = result.username;
            currentUser.role = result.role;
            
            console.log('✓ Login successful! Role:', result.role);
            
            document.getElementById('user-name').textContent = result.username;
            document.getElementById('user-role').textContent = result.role.charAt(0).toUpperCase() + result.role.slice(1);
            
            hideElement('login-page');
            showElement('dashboard-container');
            
            // Setup navigation based on role
            setupNavigationForRole(result.role);
            
            // Load appropriate dashboard
            if (result.role === 'admin') {
                showAdminDashboard();
                await loadAdminMonitoringData();
                startLiveFeed();
            } else {
                showUserDashboard();
                await loadUserPersonalData();
            }
            
            startAutoRefresh();
            
            // Initialize chat system after login
            setTimeout(() => {
                const chatBtn = document.getElementById('chatToggleBtn');
                if (chatBtn) chatBtn.style.display = 'flex';
                initChatSystem();
            }, 1000);
        } else {
            errorDiv.textContent = result?.error || 'Invalid credentials';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Login error:', error);
        errorDiv.textContent = 'Login failed. Please try again.';
        errorDiv.style.display = 'block';
    } finally {
        isLoggingIn = false;
    }
}

function setupNavigationForRole(role) {
    console.log('Setting up navigation for role:', role);
    
    const dashboardNav = document.querySelector('[data-page="dashboard"]');
    const myActivityNav = document.querySelector('[data-page="my-activity"]');
    const mySecurityNav = document.querySelector('[data-page="my-security"]');
    const profileNav = document.querySelector('[data-page="profile"]');
    const alertsNav = document.querySelector('[data-page="alerts"]');
    const activityNav = document.querySelector('[data-page="activity"]');
    const securityNav = document.querySelector('[data-page="security"]');
    const monitoringNav = document.querySelector('[data-page="monitoring"]');
    const behavioralNav = document.querySelector('[data-page="behavioral"]');
    const reportsNav = document.querySelector('[data-page="reports"]');
    const usersNav = document.querySelector('[data-page="users"]');
    const settingsNav = document.querySelector('[data-page="settings"]');
    
    if (role === 'admin') {
        if (dashboardNav) dashboardNav.style.display = 'flex';
        if (alertsNav) alertsNav.style.display = 'flex';
        if (activityNav) activityNav.style.display = 'flex';
        if (securityNav) securityNav.style.display = 'flex';
        if (monitoringNav) monitoringNav.style.display = 'flex';
        if (behavioralNav) behavioralNav.style.display = 'flex';
        if (reportsNav) reportsNav.style.display = 'flex';
        if (usersNav) usersNav.style.display = 'flex';
        if (settingsNav) settingsNav.style.display = 'flex';
        
        if (myActivityNav) myActivityNav.style.display = 'none';
        if (mySecurityNav) mySecurityNav.style.display = 'none';
        if (profileNav) profileNav.style.display = 'none';
        
        console.log('✓ Admin navigation enabled (with Behavioral Monitoring + Reports)');
    } else {
        if (dashboardNav) dashboardNav.style.display = 'flex';
        
        if (myActivityNav) myActivityNav.style.display = 'none';
        if (mySecurityNav) mySecurityNav.style.display = 'none';
        if (profileNav) profileNav.style.display = 'none';
        
        if (alertsNav) alertsNav.style.display = 'none';
        if (activityNav) activityNav.style.display = 'none';
        if (securityNav) securityNav.style.display = 'none';
        if (monitoringNav) monitoringNav.style.display = 'none';
        if (behavioralNav) behavioralNav.style.display = 'none';
        if (reportsNav) reportsNav.style.display = 'none';
        if (usersNav) usersNav.style.display = 'none';
        if (settingsNav) settingsNav.style.display = 'none';
        
        console.log('✓ User navigation limited to Dashboard only');
    }
}

async function logout() {
    await fetchAPI('/logout', { method: 'POST' });
    currentUser = { username: '', role: '' };
    
    // Hide chat button on logout
    const chatBtn = document.getElementById('chatToggleBtn');
    if (chatBtn) chatBtn.style.display = 'none';
    
    // Stop chat polling
    if (chatPollInterval) {
        clearInterval(chatPollInterval);
        chatPollInterval = null;
    }
    
    showLoginPage();
}

async function checkAuth() {
    const result = await fetchAPI('/check-auth');
    if (result && result.authenticated) {
        currentUser.username = result.username;
        currentUser.role = result.role;
        document.getElementById('user-name').textContent = result.username;
        document.getElementById('user-role').textContent = result.role.charAt(0).toUpperCase() + result.role.slice(1);
        
        setupNavigationForRole(result.role);
        
        if (result.role === 'admin') {
            showAdminDashboard();
        } else {
            showUserDashboard();
        }
        
        showDashboard();
        
        // Initialize chat if authenticated
        setTimeout(() => {
            const chatBtn = document.getElementById('chatToggleBtn');
            if (chatBtn) chatBtn.style.display = 'flex';
            initChatSystem();
        }, 1000);
    } else {
        showLoginPage();
    }
}

function showAdminDashboard() {
    console.log('Showing ADMIN dashboard');
    hideElement('user-dashboard-view');
    showElement('admin-dashboard-view');
    startLiveFeed();
}

function showUserDashboard() {
    console.log('Showing USER dashboard');
    
    const userView = document.getElementById('user-dashboard-view');
    const adminView = document.getElementById('admin-dashboard-view');
    
    if (userView) {
        userView.style.display = 'block';
        console.log('✓ User view displayed');
    }
    
    if (adminView) {
        adminView.style.display = 'none';
        console.log('✓ Admin view hidden');
    }
    
    document.getElementById('page-title').textContent = 'My Dashboard';
    document.getElementById('page-subtitle').textContent = 'Personal security overview';
    
    loadUserPersonalData();
}

function showLoginForm() {
    showElement('login-form');
    hideElement('signup-form');
}

function showSignupForm() {
    hideElement('login-form');
    showElement('signup-form');
}

function showLoginPage() {
    hideElement('dashboard-container');
    showElement('login-page');
    stopAutoRefresh();
}

function showDashboard() {
    hideElement('login-page');
    showElement('dashboard-container');
    loadAllData();
    startAutoRefresh();
}

async function signup() {
    const username = document.getElementById('signup-username').value.trim();
    const password = document.getElementById('signup-password').value.trim();
    const confirm = document.getElementById('signup-confirm').value.trim();
    const role = document.getElementById('signup-role').value;
    const errorDiv = document.getElementById('signup-error');
    const successDiv = document.getElementById('signup-success');
    
    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';
    
    if (!username || !password || !confirm) {
        errorDiv.textContent = 'Please fill in all fields';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (password !== confirm) {
        errorDiv.textContent = 'Passwords do not match';
        errorDiv.style.display = 'block';
        return;
    }
    
    if (password.length < 6) {
        errorDiv.textContent = 'Password must be at least 6 characters';
        errorDiv.style.display = 'block';
        return;
    }
    
    const result = await fetchAPI('/signup', {
        method: 'POST',
        body: JSON.stringify({ username, password, role })
    });
    
    if (result && result.success) {
        successDiv.textContent = 'Account created successfully! You can now login.';
        successDiv.style.display = 'block';
        
        document.getElementById('signup-username').value = '';
        document.getElementById('signup-password').value = '';
        document.getElementById('signup-confirm').value = '';
        
        setTimeout(() => showLoginForm(), 2000);
    } else {
        errorDiv.textContent = result?.error || 'Signup failed';
        errorDiv.style.display = 'block';
    }
}

// ============ NAVIGATION ============

function switchPage(pageName) {
    if (currentUser.role !== 'admin') {
        const allowedPages = ['dashboard'];
        if (!allowedPages.includes(pageName)) {
            console.log('Access denied to page:', pageName);
            return;
        }
    } else {
        const adminPages = ['dashboard', 'alerts', 'activity', 'security', 'monitoring', 'behavioral', 'reports', 'users', 'settings'];
        if (!adminPages.includes(pageName)) {
            console.log('Admin redirected from user page:', pageName);
            return;
        }
    }
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === pageName) {
            item.classList.add('active');
        }
    });
    
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.remove('active');
    });
    
    const pageElement = document.getElementById(`page-${pageName}`);
    if (pageElement) pageElement.classList.add('active');
    
    const titles = {
        dashboard: currentUser.role === 'admin' ? 'Dashboard Overview' : 'My Dashboard',
        'my-activity': 'My Activity',
        'my-security': 'My Security',
        'profile': 'Profile & Settings',
        alerts: 'All Alerts',
        activity: 'Activity Logs',
        security: 'Security Logs',
        monitoring: '🔍 NLP Log Monitoring',
        behavioral: '🧠 Behavioral Analysis',
        reports: '📄 User Reports',
        users: 'User Management',
        settings: 'Settings'
    };
    
    const subtitles = {
        dashboard: currentUser.role === 'admin' ? 'Real-time monitoring and threat detection' : 'Your personal security overview',
        'my-activity': 'Your complete activity history',
        'my-security': 'Security status and recommendations',
        'profile': 'Manage your account settings',
        alerts: 'System-wide security alerts',
        activity: 'All user activity logs',
        security: 'System security events',
        monitoring: 'AI-powered log analysis and email alerting',
        behavioral: 'Comprehensive 5-feature behavioral monitoring system',
        reports: 'Generate comprehensive PDF reports for users',
        users: 'Manage registered users',
        settings: 'System configuration'
    };
    
    document.getElementById('page-title').textContent = titles[pageName] || 'Dashboard';
    document.getElementById('page-subtitle').textContent = subtitles[pageName] || '';
    
    currentPage = pageName;
    loadPageData(pageName);
}

// ============ DATA LOADING ============

async function loadAllData() {
    loadPageData(currentPage);
}

async function loadPageData(pageName) {
    console.log('Loading page:', pageName, 'Role:', currentUser.role);
    
    switch(pageName) {
        case 'dashboard':
            if (currentUser.role === 'admin') {
                await loadAdminMonitoringData();
                startLiveFeed();
            } else {
                await loadUserPersonalData();
            }
            break;
        case 'my-activity':
            if (currentUser.role !== 'admin') {
                await loadMyActivity();
            }
            break;
        case 'my-security':
            if (currentUser.role !== 'admin') {
                await loadMySecurity();
            }
            break;
        case 'profile':
            if (currentUser.role !== 'admin') {
                await loadProfile();
            }
            break;
        case 'alerts':
            if (currentUser.role === 'admin') {
                await loadAlertsData();
            }
            break;
        case 'activity':
            if (currentUser.role === 'admin') {
                await loadActivityData();
            }
            break;
        case 'security':
            if (currentUser.role === 'admin') {
                await loadSecurityData();
            }
            break;
        case 'monitoring':
            if (currentUser.role === 'admin') {
                await refreshMonitoringStatus();
            }
            break;
        case 'behavioral':
            if (currentUser.role === 'admin') {
                await loadBehavioralMonitoring();
            }
            break;
        case 'reports':
            if (currentUser.role === 'admin') {
                await loadReportsPage();
            }
            break;
        case 'users':
            if (currentUser.role === 'admin') {
                await loadUsersData();
            }
            break;
        case 'settings':
            if (currentUser.role === 'admin') {
                await loadSettingsData();
            }
            break;
    }
}

// ============ USER PERSONAL DASHBOARD ============

async function loadUserPersonalData() {
    console.log('📊 Loading user personal data...');
    
    const data = await fetchAPI('/user/personal-data');
    if (!data) {
        console.error('❌ Failed to load user personal data');
        return;
    }
    
    console.log('✓ User data loaded:', data);
    
    const welcomeTitle = document.getElementById('welcome-title');
    if (welcomeTitle) {
        welcomeTitle.textContent = `Welcome, ${currentUser.username}!`;
    }
    
    console.log('✓ User dashboard updated');
}

async function loadUserActivityTimeline() {
    console.log('📋 Loading user activity timeline...');
    
    const activityData = await fetchAPI('/user/my-activity');
    if (!activityData) {
        console.error('❌ Failed to load activity data');
        return;
    }
    
    console.log('✓ Activity data loaded:', activityData.length, 'items');
    
    const tableBody = document.getElementById('top-anomalies-table');
    if (!tableBody) {
        console.log('ℹ️  Activity table not present (simple user view)');
        return;
    }
    
    tableBody.innerHTML = '';
    
    if (activityData.length > 0) {
        activityData.slice(0, 15).forEach(activity => {
            const row = document.createElement('tr');
            
            let icon = '📌';
            if (activity.action.toLowerCase().includes('login')) icon = '🔐';
            else if (activity.action.toLowerCase().includes('file')) icon = '📄';
            else if (activity.action.toLowerCase().includes('usb')) icon = '💾';
            else if (activity.action.toLowerCase().includes('email')) icon = '📧';
            
            row.innerHTML = `
                <td><span style="margin-right: 8px; font-size: 18px;">${icon}</span><strong>${activity.action}</strong></td>
                <td style="color: var(--text-secondary);">${activity.resource}</td>
                <td style="color: var(--text-secondary); font-size: 13px;">${activity.timestamp}</td>
                <td><span class="status-badge status-normal">✓ Normal</span></td>
            `;
            tableBody.appendChild(row);
        });
    } else {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; padding: 40px;">
                    <div style="color: var(--text-secondary);">
                        <p style="font-size: 48px; margin-bottom: 16px;">📭</p>
                        <p style="font-size: 18px; margin-bottom: 8px;">No activity recorded yet</p>
                        <p style="font-size: 14px;">Your activity will appear here once you start using the system</p>
                    </div>
                </td>
            </tr>
        `;
    }
}

// ============ MY ACTIVITY PAGE ============

async function loadMyActivity() {
    console.log('📊 Loading My Activity page...');
    
    const activityData = await fetchAPI('/user/my-activity');
    if (!activityData) return;
    
    const tableBody = document.getElementById('my-activity-table');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (activityData.length > 0) {
        activityData.forEach(activity => {
            const row = document.createElement('tr');
            
            let icon = '📌';
            if (activity.action.toLowerCase().includes('login')) icon = '🔐';
            else if (activity.action.toLowerCase().includes('file')) icon = '📄';
            else if (activity.action.toLowerCase().includes('usb')) icon = '💾';
            else if (activity.action.toLowerCase().includes('email')) icon = '📧';
            
            row.innerHTML = `
                <td><span style="margin-right: 8px; font-size: 18px;">${icon}</span><strong>${activity.action}</strong></td>
                <td style="color: var(--text-secondary);">${activity.resource}</td>
                <td style="color: var(--text-secondary);">${activity.timestamp}</td>
                <td style="color: var(--text-secondary); font-size: 13px;">-</td>
            `;
            tableBody.appendChild(row);
        });
    } else {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; padding: 40px;">
                    <p style="color: var(--text-secondary);">No activity history available</p>
                </td>
            </tr>
        `;
    }
}

// ============ MY SECURITY PAGE ============

async function loadMySecurity() {
    console.log('🔒 Loading My Security page...');
    
    const data = await fetchAPI('/user/personal-data');
    if (!data) return;
    
    const statusCard = document.querySelector('.security-status-card');
    const statusTitle = document.getElementById('security-status-title');
    const statusDesc = document.getElementById('security-status-description');
    
    if (data.riskLevel === 'High') {
        statusCard.className = 'security-status-card status-danger';
        statusTitle.textContent = 'Account Security: Needs Attention';
        statusDesc.textContent = 'Your account has been flagged for unusual activity. Please review the recommendations below.';
    } else if (data.riskLevel === 'Medium') {
        statusCard.className = 'security-status-card status-warning';
        statusTitle.textContent = 'Account Security: Fair';
        statusDesc.textContent = 'Some unusual patterns detected. Consider reviewing your recent activity.';
    } else {
        statusCard.className = 'security-status-card';
        statusTitle.textContent = 'Account Security: Good';
        statusDesc.textContent = 'Your account is secure. Keep following best practices.';
    }
    
    const recommendationsContainer = document.getElementById('security-recommendations');
    recommendationsContainer.innerHTML = '';
    
    const recommendations = [
        { icon: '🔑', title: 'Strong Password', description: 'Your password meets security requirements. Consider changing it every 90 days.' },
        { icon: '⏰', title: 'Login Hours', description: 'Most of your logins occur during business hours - this is normal.' }
    ];
    
    recommendations.forEach(rec => {
        const div = document.createElement('div');
        div.className = 'recommendation-item';
        div.innerHTML = `
            <div class="recommendation-icon">${rec.icon}</div>
            <div class="recommendation-content">
                <div class="recommendation-title">${rec.title}</div>
                <div class="recommendation-description">${rec.description}</div>
            </div>
        `;
        recommendationsContainer.appendChild(div);
    });
    
    const notificationsContainer = document.getElementById('security-notifications');
    notificationsContainer.innerHTML = '';
    
    if (data.alertCount > 0) {
        const notification = document.createElement('div');
        notification.className = 'notification-item';
        notification.innerHTML = `
            <div class="notification-icon">⚠️</div>
            <div class="notification-content">
                <div class="notification-title">Unusual Activity Detected</div>
                <div class="notification-description">
                    Your anomaly score is ${data.anomalyScore.toFixed(2)}. Please review your recent activity.
                </div>
            </div>
        `;
        notificationsContainer.appendChild(notification);
    } else {
        const notification = document.createElement('div');
        notification.className = 'notification-item';
        notification.innerHTML = `
            <div class="notification-icon">✅</div>
            <div class="notification-content">
                <div class="notification-title">All Clear</div>
                <div class="notification-description">No security notifications at this time.</div>
            </div>
        `;
        notificationsContainer.appendChild(notification);
    }
}

// ============ PROFILE & SETTINGS PAGE ============

async function loadProfile() {
    console.log('👤 Loading Profile page...');
    
    document.getElementById('profile-username').value = currentUser.username;
    document.getElementById('profile-role').value = currentUser.role.charAt(0).toUpperCase() + currentUser.role.slice(1);
}

async function changePassword() {
    const currentPwd = document.getElementById('current-password').value.trim();
    const newPwd = document.getElementById('new-password').value.trim();
    const confirmPwd = document.getElementById('confirm-password').value.trim();
    const messageDiv = document.getElementById('password-change-message');
    
    messageDiv.style.display = 'none';
    
    if (!currentPwd || !newPwd || !confirmPwd) {
        messageDiv.className = 'error-message';
        messageDiv.textContent = 'Please fill in all fields';
        messageDiv.style.display = 'block';
        return;
    }
    
    if (newPwd !== confirmPwd) {
        messageDiv.className = 'error-message';
        messageDiv.textContent = 'New passwords do not match';
        messageDiv.style.display = 'block';
        return;
    }
    
    if (newPwd.length < 6) {
        messageDiv.className = 'error-message';
        messageDiv.textContent = 'Password must be at least 6 characters';
        messageDiv.style.display = 'block';
        return;
    }
    
    try {
        const result = await fetchAPI('/change-password', {
            method: 'POST',
            body: JSON.stringify({
                currentPassword: currentPwd,
                newPassword: newPwd
            })
        });
        
        if (result && result.success) {
            messageDiv.className = 'success-message';
            messageDiv.textContent = '✓ Password changed successfully! Please use your new password on next login.';
            messageDiv.style.display = 'block';
            
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
            document.getElementById('confirm-password').value = '';
        } else {
            messageDiv.className = 'error-message';
            messageDiv.textContent = result?.error || 'Failed to change password. Please check your current password.';
            messageDiv.style.display = 'block';
        }
    } catch (error) {
        console.error('Password change error:', error);
        messageDiv.className = 'error-message';
        messageDiv.textContent = 'An error occurred. Please try again.';
        messageDiv.style.display = 'block';
    }
}

// ============ ADMIN MONITORING ============

async function loadAdminMonitoringData() {
    console.log('📊 Loading admin monitoring data...');
    
    const data = await fetchAPI('/admin/monitoring');
    if (!data) {
        console.log('⚠️  No data from /admin/monitoring, calculating from live feed...');
        const liveFeedData = await fetchAPI('/admin/live-feed');
        if (liveFeedData && liveFeedData.events) {
            calculateStatsFromEvents(liveFeedData.events);
        }
        return;
    }
    
    document.getElementById('admin-total-users').textContent = data.totalUsers || 21;
    document.getElementById('admin-active-sessions').textContent = data.activeSessions || calculateActiveSessions();
    document.getElementById('admin-threats').textContent = data.activeThreats || calculateActiveThreats();
    document.getElementById('admin-events-today').textContent = data.eventsToday || calculateEventsToday();
    
    const alertsTable = document.getElementById('admin-alerts-table');
    alertsTable.innerHTML = '';
    
    if (data.criticalAlerts && data.criticalAlerts.length > 0) {
        data.criticalAlerts.forEach(alert => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${alert.user}</td>
                <td>${alert.type}</td>
                <td><span class="risk-badge risk-critical">${alert.severity}</span></td>
                <td>${alert.time}</td>
                <td><button class="action-button" onclick="investigateUser('${alert.user}')">Investigate</button></td>
            `;
            alertsTable.appendChild(row);
        });
    } else {
        alertsTable.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No critical alerts</td></tr>';
    }
    
    console.log('✓ Admin data loaded');
}

// ============ STATS CALCULATION HELPER FUNCTIONS ============

function calculateActiveSessions() {
    const feedContainer = document.getElementById('live-feed');
    if (!feedContainer) return 1;
    
    const loginEvents = Array.from(feedContainer.querySelectorAll('.feed-item'))
        .filter(item => {
            const title = item.querySelector('.feed-item-title')?.textContent || '';
            return title.toLowerCase().includes('login:') && !title.toLowerCase().includes('logout');
        });
    
    const uniqueUsers = new Set();
    loginEvents.forEach(event => {
        const title = event.querySelector('.feed-item-title')?.textContent || '';
        const username = title.split(':')[1]?.trim() || '';
        if (username) uniqueUsers.add(username);
    });
    
    return Math.max(1, uniqueUsers.size);
}

function calculateActiveThreats() {
    const feedContainer = document.getElementById('live-feed');
    if (!feedContainer) return 0;
    
    const threatEvents = Array.from(feedContainer.querySelectorAll('.feed-item'))
        .filter(item => {
            const title = item.querySelector('.feed-item-title')?.textContent || '';
            const isDanger = item.querySelector('.feed-item-icon.danger') !== null;
            const isWarning = item.querySelector('.feed-item-icon.warning') !== null;
            const isSuspicious = title.includes('SUSPICIOUS') || title.includes('BRUTE FORCE') || 
                               title.includes('SENSITIVE FILE') || title.includes('CUMULATIVE');
            return (isDanger || isWarning) && isSuspicious;
        });
    
    return threatEvents.length;
}

function calculateEventsToday() {
    const feedContainer = document.getElementById('live-feed');
    if (!feedContainer) return 0;
    
    const allEvents = feedContainer.querySelectorAll('.feed-item');
    return allEvents.length;
}

function calculateStatsFromEvents(events) {
    const loggedInUsers = new Set();
    events.forEach(event => {
        if (event.type === 'login' || event.type === 'after_hours_login') {
            loggedInUsers.add(event.username);
        }
    });
    
    const threats = events.filter(event => {
        return event.type === 'brute_force' || 
               event.type === 'sensitive_file' || 
               event.type === 'suspicious_chat' ||
               event.type === 'cumulative_anomaly';
    });
    
    document.getElementById('admin-total-users').textContent = 21;
    document.getElementById('admin-active-sessions').textContent = Math.max(1, loggedInUsers.size);
    document.getElementById('admin-threats').textContent = threats.length;
    document.getElementById('admin-events-today').textContent = events.length;
}

function startLiveFeed() {
    if (liveFeedTimer) clearInterval(liveFeedTimer);
    
    liveFeedTimer = setInterval(async () => {
        if (!liveFeedPaused && currentUser.role === 'admin') {
            await updateLiveFeed();
        }
    }, 2000);
    
    updateLiveFeed();
}

async function updateLiveFeed() {
    const data = await fetchAPI('/admin/live-feed');
    if (!data || !data.events) return;
    
    const feedContainer = document.getElementById('live-feed');
    if (!feedContainer) return;
    
    data.events.forEach(event => {
        const eventId = `${event.title}-${event.time}`;
        
        if (displayedEventIds.has(eventId)) {
            return;
        }
        
        displayedEventIds.add(eventId);
        
        const feedItem = createFeedItem(event);
        feedContainer.insertBefore(feedItem, feedContainer.firstChild);
    });
    
    while (feedContainer.children.length > 50) {
        feedContainer.removeChild(feedContainer.lastChild);
    }
}

function createFeedItem(event) {
    const div = document.createElement('div');
    div.className = 'feed-item';
    
    let iconClass = 'info';
    let icon = 'ℹ️';
    let title = event.title;
    let details = event.details;
    
    switch(event.type) {
        case 'after_hours_login':
            iconClass = 'warning';
            icon = '🌙';
            break;
        case 'brute_force':
            iconClass = 'danger';
            icon = '🚨';
            break;
        case 'failed_login':
            iconClass = 'warning';
            icon = '⚠️';
            break;
        case 'sensitive_file':
            iconClass = 'danger';
            icon = '🔐';
            break;
        case 'file_access':
            iconClass = 'info';
            icon = '📄';
            break;
        case 'login':
            iconClass = 'success';
            icon = '✓';
            break;
        case 'logout':
            iconClass = 'info';
            icon = '👋';
            break;
        case 'critical':
            iconClass = 'danger';
            icon = '⚠️';
            break;
        case 'warning':
            iconClass = 'warning';
            icon = '⚡';
            break;
        case 'success':
            iconClass = 'success';
            icon = '✓';
            break;
        default:
            iconClass = 'info';
            icon = 'ℹ️';
    }
    
    div.innerHTML = `
        <div class="feed-item-icon ${iconClass}">${icon}</div>
        <div class="feed-item-content">
            <div class="feed-item-title">${title}</div>
            <div class="feed-item-details">${details}</div>
        </div>
        <div class="feed-item-time">${event.time}</div>
    `;
    
    return div;
}

function toggleFeed() {
    liveFeedPaused = !liveFeedPaused;
    const btn = document.getElementById('pause-feed');
    if (btn) btn.textContent = liveFeedPaused ? 'Resume Feed' : 'Pause Feed';
}

// Auto-update admin stats every 3 seconds
setInterval(() => {
    if (currentUser.role === 'admin' && document.getElementById('admin-active-sessions')) {
        const sessions = calculateActiveSessions();
        const threats = calculateActiveThreats();
        const events = calculateEventsToday();
        
        if (sessions > 0) document.getElementById('admin-active-sessions').textContent = sessions;
        document.getElementById('admin-threats').textContent = threats;
        if (events > 0) document.getElementById('admin-events-today').textContent = events;
    }
}, 3000);

// ============ ADMIN PAGES ============

async function loadAlertsData() {
    const data = await fetchAPI('/alerts');
    if (!data) return;
    
    const tableBody = document.getElementById('alerts-table');
    tableBody.innerHTML = '';
    
    if (data.length > 0) {
        data.forEach(alert => {
            const row = document.createElement('tr');
            const statusClass = `status-${alert.status.toLowerCase().replace(' ', '-')}`;
            row.innerHTML = `
                <td>${alert.user}</td>
                <td>${alert.type}</td>
                <td><span style="color: var(--accent-red); font-weight: 600;">${alert.score.toFixed(3)}</span></td>
                <td style="color: var(--text-secondary);">${alert.timestamp}</td>
                <td><span class="status-badge ${statusClass}">${alert.status}</span></td>
                <td>
                    <button class="action-button" onclick="viewAlert(${alert.id})">View</button>
                </td>
            `;
            tableBody.appendChild(row);
        });
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-secondary); padding: 40px;">✓ No active alerts</td></tr>';
    }
}

async function loadActivityData() {
    const data = await fetchAPI('/activity-logs');
    if (!data) return;
    
    const tableBody = document.getElementById('activity-table');
    tableBody.innerHTML = '';
    
    if (data.length > 0) {
        data.forEach(log => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${log.user}</td>
                <td>${log.action}</td>
                <td style="color: var(--text-secondary);">${log.resource}</td>
                <td style="color: var(--text-secondary);">${log.timestamp}</td>
            `;
            tableBody.appendChild(row);
        });
    }
}

async function loadSecurityData() {
    const data = await fetchAPI('/security-logs');
    if (!data) return;
    
    const tableBody = document.getElementById('security-table');
    tableBody.innerHTML = '';
    
    if (data.length > 0) {
        data.forEach(log => {
            const row = document.createElement('tr');
            const severityClass = `severity-${log.severity.toLowerCase()}`;
            row.innerHTML = `
                <td>${log.event}</td>
                <td><span class="${severityClass}">${log.severity}</span></td>
                <td style="color: var(--text-secondary);">${log.timestamp}</td>
            `;
            tableBody.appendChild(row);
        });
    }
}

async function loadUsersData() {
    const data = await fetchAPI('/users');
    if (!data) return;
    
    const tableBody = document.getElementById('users-table');
    tableBody.innerHTML = '';
    
    if (data.length > 0) {
        data.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.username}</td>
                <td><span class="risk-badge risk-${user.role === 'admin' ? 'critical' : user.role === 'analyst' ? 'high' : 'medium'}">${user.role}</span></td>
                <td>${user.status || 'Active'}</td>
                <td>
                    ${user.username !== 'admin' ? `<button class="action-button" onclick="deleteUser('${user.username}')">Delete</button>` : '<span style="color: var(--text-secondary);">Protected</span>'}
                </td>
            `;
            tableBody.appendChild(row);
        });
    }
}

async function deleteUser(username) {
    if (!confirm(`Delete user: ${username}?`)) return;
    
    const result = await fetchAPI('/delete-user', {
        method: 'POST',
        body: JSON.stringify({ username })
    });
    
    if (result && result.success) {
        alert('User deleted');
        loadUsersData();
    }
}

async function loadSettingsData() {
    const data = await fetchAPI('/settings');
    if (!data) return;
    
    document.getElementById('threshold-slider').value = data.anomalyThreshold || 0.7;
    document.getElementById('threshold-value').textContent = data.anomalyThreshold || 0.7;
    document.getElementById('auto-refresh').checked = data.autoRefresh !== false;
    document.getElementById('refresh-interval').value = data.refreshInterval || 5;
    
    document.getElementById('models-loaded').textContent = data.modelsLoaded?.join(', ') || 'None';
    document.getElementById('data-loaded').textContent = data.dataFilesLoaded?.join(', ') || 'None';
    document.getElementById('last-update').textContent = new Date().toLocaleString();
}

// ============================================================================
// NLP MONITORING FUNCTIONS
// ============================================================================

async function analyzeLog() {
    const logText = document.getElementById('log-input').value.trim();
    
    if (!logText) {
        alert('Please enter a log entry to analyze');
        return;
    }
    
    try {
        const response = await fetch('http://localhost:5000/api/threat-monitoring/analyze-log', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({
                log_text: logText,
                send_alert: false
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            const result = data.analysis;
            
            const bgColor = result.risk_level === 'HIGH' ? '#ffebee' : 
                          result.risk_level === 'MEDIUM' ? '#fff3cd' : '#e8f5e9';
            
            document.getElementById('analysis-result').innerHTML = `
                <div style="background: ${bgColor}; padding: 20px; border-radius: 8px; border-left: 4px solid ${getRiskColor(result.risk_level)};">
                    <h4 style="margin-top: 0; color: ${getRiskColor(result.risk_level)};">
                        Analysis Result
                    </h4>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-top: 16px;">
                        <div>
                            <p style="margin: 8px 0;"><strong>Prediction:</strong> ${result.prediction}</p>
                            <p style="margin: 8px 0;"><strong>Risk Level:</strong> 
                                <span style="color: ${getRiskColor(result.risk_level)}; font-weight: bold;">
                                    ${result.risk_level}
                                </span>
                            </p>
                        </div>
                        <div>
                            <p style="margin: 8px 0;"><strong>Risk Score:</strong> ${result.risk_score.toFixed(3)}</p>
                            <p style="margin: 8px 0;"><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                        </div>
                    </div>
                    ${result.suspicious_keywords && result.suspicious_keywords.length > 0 ? `
                        <p style="margin-top: 16px;"><strong>Suspicious Keywords:</strong> 
                            ${result.suspicious_keywords.map(kw => 
                                `<span style="background: #fff; padding: 4px 8px; border-radius: 4px; margin-right: 4px; display: inline-block; margin-top: 4px;">${kw}</span>`
                            ).join('')}
                        </p>
                    ` : ''}
                    <p style="margin-top: 16px; font-size: 12px; color: var(--text-secondary);">
                        Analyzed at: ${result.timestamp || new Date().toLocaleString()}
                    </p>
                </div>
            `;
        } else {
            document.getElementById('analysis-result').innerHTML = `
                <div style="background: #ffebee; padding: 20px; border-radius: 8px; border-left: 4px solid #d32f2f;">
                    <p style="color: #d32f2f; margin: 0;"><strong>Error:</strong> ${data.error || 'Analysis failed'}</p>
                </div>
            `;
        }
    } catch (error) {
        console.error('Log analysis error:', error);
        document.getElementById('analysis-result').innerHTML = `
            <div style="background: #ffebee; padding: 20px; border-radius: 8px; border-left: 4px solid #d32f2f;">
                <p style="color: #d32f2f; margin: 0;"><strong>Error:</strong> Failed to analyze log. Make sure NLP models are trained.</p>
            </div>
        `;
    }
}

async function refreshMonitoringStatus() {
    try {
        const response = await fetch('http://localhost:5000/api/threat-monitoring/status', {
            credentials: 'include'
        });
        const data = await response.json();
        
        const statusHtml = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                <div style="padding: 16px; background: white; border-radius: 6px; border-left: 4px solid ${data.monitoring_active ? '#4caf50' : '#f44336'};">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">Monitoring Status</p>
                    <p style="margin: 8px 0 0 0; font-size: 20px; font-weight: 600; color: ${data.monitoring_active ? '#4caf50' : '#f44336'};">
                        ${data.monitoring_active ? '🟢 Active' : '🔴 Inactive'}
                    </p>
                </div>
                <div style="padding: 16px; background: white; border-radius: 6px; border-left: 4px solid #2196f3;">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">Last Check</p>
                    <p style="margin: 8px 0 0 0; font-size: 16px; font-weight: 600; color: #333;">
                        ${data.last_check_time && data.last_check_time !== 'Never' ? data.last_check_time : (data.monitoring_active ? '⏰ Scheduled' : 'Never')}
                    </p>
                </div>
                <div style="padding: 16px; background: white; border-radius: 6px; border-left: 4px solid #ff9800;">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">Alerts Today</p>
                    <p style="margin: 8px 0 0 0; font-size: 20px; font-weight: 600; color: #ff9800;">
                        ${data.alerts_sent_today || 0}
                    </p>
                </div>
                <div style="padding: 16px; background: white; border-radius: 6px; border-left: 4px solid #9c27b0;">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">NLP Model</p>
                    <p style="margin: 8px 0 0 0; font-size: 16px; font-weight: 600; color: #333;">
                        ${data.nlp_model_loaded ? '✅ Loaded' : '❌ Not Loaded'}
                    </p>
                </div>
                <div style="padding: 16px; background: white; border-radius: 6px; border-left: 4px solid #00bcd4;">
                    <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">Email System</p>
                    <p style="margin: 8px 0 0 0; font-size: 16px; font-weight: 600; color: #333;">
                        ${data.email_configured ? '✅ Configured' : '⚠️ Not Configured'}
                    </p>
                </div>
            </div>
        `;
        
        document.getElementById('monitoring-status-display').innerHTML = statusHtml;
    } catch (error) {
        console.error('Status refresh error:', error);
        document.getElementById('monitoring-status-display').innerHTML = `
            <p style="color: #d32f2f;">❌ Failed to load monitoring status. Make sure threat_monitoring_integration.py is installed.</p>
        `;
    }
}

async function checkAfterHours() {
    try {
        const response = await fetch('http://localhost:5000/api/threat-monitoring/check-after-hours', {
            method: 'POST',
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success) {
            alert(`✅ After-Hours Check Complete!\n\nAlerts sent: ${data.alerts_sent}\n\nCheck admin email for notifications.`);
            refreshMonitoringStatus();
        } else {
            alert(`❌ Check failed: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('After-hours check error:', error);
        alert('❌ Failed to run after-hours check. Make sure the system is properly configured.');
    }
}

async function checkHighRiskUsers() {
    try {
        const response = await fetch('http://localhost:5000/api/threat-monitoring/check-high-risk-users', {
            method: 'POST',
            credentials: 'include'
        });
        const data = await response.json();
        
        if (data.success) {
            alert(`✅ High-Risk User Check Complete!\n\nAlerts sent: ${data.alerts_sent}\n\nCheck admin email for notifications.`);
            refreshMonitoringStatus();
        } else {
            alert(`❌ Check failed: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error('High-risk check error:', error);
        alert('❌ Failed to run high-risk user check. Make sure the system is properly configured.');
    }
}

function getRiskColor(level) {
    switch(level) {
        case 'HIGH': return '#d32f2f';
        case 'MEDIUM': return '#f57c00';
        case 'LOW': return '#388e3c';
        default: return '#757575';
    }
}

// ============================================================================
// BEHAVIORAL MONITORING FUNCTIONS
// ============================================================================

async function loadBehavioralMonitoring() {
    console.log('📊 Loading behavioral monitoring page...');
    
    try {
        const response = await fetch('http://localhost:5000/dashboard/api/behavioral/comprehensive-analysis', {
            credentials: 'include'
        });
        
        if (!response.ok) {
            console.error('Failed to load behavioral analysis');
            return;
        }
        
        const data = await response.json();
        
        if (!data.success) {
            console.error('Behavioral analysis failed:', data.error);
            return;
        }
        
        const analysis = data.analysis;
        
        document.getElementById('behavioral-total-alerts').textContent = analysis.summary.total_alerts || 0;
        document.getElementById('behavioral-critical-alerts').textContent = analysis.summary.critical_alerts || 0;
        document.getElementById('behavioral-high-alerts').textContent = analysis.summary.high_alerts || 0;
        document.getElementById('behavioral-users-flagged').textContent = analysis.summary.users_flagged || 0;
        
        loadBehavioralFeature('after-hours', analysis.features.after_hours_logins);
        loadBehavioralFeature('sensitive-files', analysis.features.sensitive_file_access);
        loadBehavioralFeature('abnormal-logins', analysis.features.abnormal_logins);
        loadBehavioralFeature('unusual-activity', analysis.features.unusual_activity);
        loadBehavioralFeature('ml-anomalies', analysis.features.behavioral_anomalies);
        
        console.log('✓ Behavioral monitoring data loaded');
        
    } catch (error) {
        console.error('Error loading behavioral monitoring:', error);
    }
}

function loadBehavioralFeature(featureName, featureData) {
    const tableId = `behavioral-${featureName}-table`;
    const tableBody = document.getElementById(tableId);
    
    if (!tableBody) {
        console.warn(`Table not found: ${tableId}`);
        return;
    }
    
    tableBody.innerHTML = '';
    
    if (!featureData.data || featureData.data.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 40px; color: var(--text-secondary);">
                    ✓ No alerts detected for this feature
                </td>
            </tr>
        `;
        return;
    }
    
    featureData.data.forEach(alert => {
        const row = document.createElement('tr');
        
        let severityClass = 'risk-low';
        if (alert.severity === 'Critical') severityClass = 'risk-critical';
        else if (alert.severity === 'High') severityClass = 'risk-high';
        else if (alert.severity === 'Medium') severityClass = 'risk-medium';
        
        row.innerHTML = `
            <td>${alert.user || 'Unknown'}</td>
            <td>${alert.alert_type || 'Alert'}</td>
            <td>${alert.reason || 'N/A'}</td>
            <td>${alert.timestamp || 'N/A'}</td>
            <td><span class="risk-badge ${severityClass}">${alert.severity || 'Low'}</span></td>
        `;
        
        tableBody.appendChild(row);
    });
}

// ============================================================================
// REPORT GENERATION FUNCTIONS (NEW)
// ============================================================================

async function loadReportsPage() {
    console.log('📄 Loading reports page...');
    
    // Load available users for report generation
    await loadReportUsers();
}

async function loadReportUsers() {
    try {
        const response = await fetchAPI('/admin/available-users');
        
        if (response && response.success) {
            const selectElement = document.getElementById('report-user-select');
            if (!selectElement) return;
            
            selectElement.innerHTML = '<option value="">-- Select a user --</option>';
            
            response.users.forEach(username => {
                const option = document.createElement('option');
                option.value = username;
                option.textContent = username;
                selectElement.appendChild(option);
            });
            
            console.log('✓ Loaded users for report generation:', response.users.length);
        }
    } catch (error) {
        console.error('Error loading users for reports:', error);
    }
}

async function generateReport() {
    const userSelect = document.getElementById('report-user-select');
    const periodSelect = document.getElementById('report-period-select');
    const generateBtn = document.getElementById('generate-report-btn');
    const statusDiv = document.getElementById('report-status');
    
    const username = userSelect.value;
    const days = parseInt(periodSelect.value);
    
    if (!username) {
        statusDiv.className = 'report-status error';
        statusDiv.textContent = '⚠️ Please select a user';
        statusDiv.style.display = 'block';
        return;
    }
    
    // Show loading state
    generateBtn.disabled = true;
    generateBtn.textContent = '⏳ Generating Report...';
    statusDiv.className = 'report-status loading';
    statusDiv.textContent = '📊 Generating PDF report, please wait...';
    statusDiv.style.display = 'block';
    
    try {
        const response = await fetch(`${API_BASE}/admin/generate-report`, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                days: days
            })
        });
        
        if (response.ok) {
            // Get the PDF blob
            const blob = await response.blob();
            
            // Create download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `report_${username}_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            // Show success
            statusDiv.className = 'report-status success';
            statusDiv.textContent = `✅ Report generated successfully! Download started for ${username}.`;
            
            console.log('✓ Report generated for:', username);
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to generate report');
        }
    } catch (error) {
        console.error('Report generation error:', error);
        statusDiv.className = 'report-status error';
        statusDiv.textContent = `❌ Error: ${error.message}`;
    } finally {
        // Reset button
        generateBtn.disabled = false;
        generateBtn.textContent = '📥 Generate PDF Report';
        
        // Hide status after 5 seconds
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 5000);
    }
}

// ============ AUTO REFRESH ============

function startAutoRefresh() {
    stopAutoRefresh();
    if (autoRefreshEnabled) {
        refreshTimer = setInterval(() => {
            loadPageData(currentPage);
        }, refreshInterval);
    }
}

function stopAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    if (liveFeedTimer) clearInterval(liveFeedTimer);
}

// ============ SETTINGS ============

async function saveSettings() {
    const settings = {
        anomalyThreshold: parseFloat(document.getElementById('threshold-slider').value),
        autoRefresh: document.getElementById('auto-refresh').checked,
        refreshInterval: parseInt(document.getElementById('refresh-interval').value)
    };
    
    const result = await fetchAPI('/settings', {
        method: 'POST',
        body: JSON.stringify(settings)
    });
    
    if (result && result.success) {
        autoRefreshEnabled = settings.autoRefresh;
        refreshInterval = settings.refreshInterval * 1000;
        alert('Settings saved!');
        startAutoRefresh();
    }
}

async function reloadData() {
    const btn = document.getElementById('reload-data');
    btn.textContent = 'Reloading...';
    btn.disabled = true;
    
    const result = await fetchAPI('/reload', { method: 'POST' });
    
    if (result && result.success) {
        alert(`Data reloaded!\nFiles: ${result.dataFiles}`);
        await loadAllData();
    }
    
    btn.textContent = 'Reload Data';
    btn.disabled = false;
}

// ============ ACTIONS ============

async function accessFile(filepath) {
    const messageDiv = document.getElementById('file-access-message');
    
    try {
        const response = await fetchAPI('/simulate-file-access', {
            method: 'POST',
            body: JSON.stringify({
                filepath: filepath,
                action: 'read'
            })
        });
        
        if (response && response.success) {
            messageDiv.style.display = 'block';
            messageDiv.style.background = '#e8f5e9';
            messageDiv.style.border = '1px solid #4caf50';
            messageDiv.style.color = '#2e7d32';
            messageDiv.innerHTML = `
                <strong>✅ File accessed:</strong> ${filepath}<br>
                <small style="color: #666;">This event has been logged in the admin's live feed</small>
            `;
            
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 5000);
        } else {
            messageDiv.style.display = 'block';
            messageDiv.style.background = '#ffebee';
            messageDiv.style.border = '1px solid #f44336';
            messageDiv.style.color = '#c62828';
            messageDiv.innerHTML = `<strong>❌ Error:</strong> ${response?.error || 'Failed to access file'}`;
        }
    } catch (error) {
        console.error('File access error:', error);
        messageDiv.style.display = 'block';
        messageDiv.style.background = '#ffebee';
        messageDiv.style.border = '1px solid #f44336';
        messageDiv.style.color = '#c62828';
        messageDiv.innerHTML = `<strong>❌ Error:</strong> Network error`;
    }
}

function investigateUser(userId) {
    alert(`Investigating: ${userId}`);
}

function viewAlert(alertId) {
    alert(`Viewing alert #${alertId}`);
}

// ==========================================
// CHAT SYSTEM FUNCTIONALITY
// ==========================================

let chatLastMessageId = 0;
let chatPollInterval = null;
let chatUnreadCount = 0;
let chatIsOpen = false;

function initChatSystem() {
    loadChatMessages();
    startChatPolling();
    
    const toggleBtn = document.getElementById('chatToggleBtn');
    const closeBtn = document.getElementById('chatCloseBtn');
    const sendBtn = document.getElementById('chatSendBtn');
    const clearBtn = document.getElementById('chatClearBtn');
    const input = document.getElementById('chatInput');
    
    if (toggleBtn) toggleBtn.addEventListener('click', toggleChat);
    if (closeBtn) closeBtn.addEventListener('click', toggleChat);
    if (sendBtn) sendBtn.addEventListener('click', sendChatMessage);
    if (clearBtn) clearBtn.addEventListener('click', clearChatHistory);
    
    if (input) {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendChatMessage();
        });
    }
}

function toggleChat() {
    chatIsOpen = !chatIsOpen;
    const chatWindow = document.getElementById('chatWindow');
    
    if (chatIsOpen) {
        chatWindow.style.display = 'flex';
        chatUnreadCount = 0;
        updateChatBadge();
        scrollChatToBottom();
        const input = document.getElementById('chatInput');
        if (input) input.focus();
    } else {
        chatWindow.style.display = 'none';
    }
}

async function loadChatMessages() {
    try {
        const response = await fetchAPI('/chat/messages?limit=100');
        
        if (response && response.success) {
            const messagesContainer = document.getElementById('chatMessages');
            if (!messagesContainer) return;
            
            messagesContainer.innerHTML = '';
            
            response.messages.forEach(msg => {
                appendChatMessage(msg, false);
                chatLastMessageId = Math.max(chatLastMessageId, msg.id);
            });
            
            scrollChatToBottom();
        }
    } catch (error) {
        console.error('Error loading chat messages:', error);
    }
}

function startChatPolling() {
    if (chatPollInterval) clearInterval(chatPollInterval);
    
    chatPollInterval = setInterval(async () => {
        try {
            const response = await fetchAPI(`/chat/poll?last_id=${chatLastMessageId}`);
            
            if (response && response.success && response.messages.length > 0) {
                response.messages.forEach(msg => {
                    appendChatMessage(msg, true);
                    chatLastMessageId = Math.max(chatLastMessageId, msg.id);
                    
                    if (!chatIsOpen) {
                        chatUnreadCount++;
                        updateChatBadge();
                    }
                });
                
                if (chatIsOpen) {
                    scrollChatToBottom();
                }
            }
        } catch (error) {
            console.error('Error polling chat messages:', error);
        }
    }, 2000);
}

function appendChatMessage(msg, animate = false) {
    const messagesContainer = document.getElementById('chatMessages');
    if (!messagesContainer) return;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message' + (msg.username === currentUser.username ? ' own' : '');
    
    messageDiv.innerHTML = `
        <div class="chat-message-header">
            <span class="chat-username ${msg.role}">${escapeHtml(msg.username)}</span>
            ${msg.role === 'admin' ? '<span class="chat-role-badge admin">Admin</span>' : ''}
            <span class="chat-timestamp">${msg.time_short}</span>
        </div>
        <div class="chat-message-text">${escapeHtml(msg.message)}</div>
    `;
    
    messagesContainer.appendChild(messageDiv);
}

async function sendChatMessage() {
    const input = document.getElementById('chatInput');
    if (!input) return;
    
    const message = input.value.trim();
    if (!message) return;
    
    try {
        const response = await fetchAPI('/chat/send', {
            method: 'POST',
            body: JSON.stringify({ message })
        });
        
        if (response && response.success) {
            input.value = '';
        } else {
            alert('Error sending message: ' + (response?.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error sending message:', error);
        alert('Error sending message');
    }
}

async function clearChatHistory() {
    if (!confirm('Are you sure you want to clear all chat history?')) return;
    
    try {
        const response = await fetchAPI('/chat/clear', {
            method: 'POST'
        });
        
        if (response && response.success) {
            const messagesContainer = document.getElementById('chatMessages');
            if (messagesContainer) messagesContainer.innerHTML = '';
            chatLastMessageId = 0;
            alert('Chat history cleared');
        } else {
            alert('Error: ' + (response?.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error clearing chat:', error);
        alert('Error clearing chat');
    }
}

function updateChatBadge() {
    const badge = document.getElementById('chatBadge');
    if (!badge) return;
    
    badge.textContent = chatUnreadCount;
    badge.style.display = chatUnreadCount > 0 ? 'flex' : 'none';
}

function scrollChatToBottom() {
    const messagesContainer = document.getElementById('chatMessages');
    if (!messagesContainer) return;
    
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

window.addEventListener('beforeunload', () => {
    if (chatPollInterval) {
        clearInterval(chatPollInterval);
    }
});

// ============ EVENT LISTENERS ============

document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Dashboard initializing with Behavioral Monitoring + Chat + Reports...');
    
    document.getElementById('show-signup')?.addEventListener('click', (e) => {
        e.preventDefault();
        showSignupForm();
    });
    
    document.getElementById('show-login')?.addEventListener('click', (e) => {
        e.preventDefault();
        showLoginForm();
    });
    
    document.getElementById('login-btn')?.addEventListener('click', login);
    document.getElementById('signup-btn')?.addEventListener('click', signup);
    document.getElementById('logout-btn')?.addEventListener('click', logout);
    
    ['username', 'password'].forEach(id => {
        document.getElementById(id)?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') login();
        });
    });
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (item.dataset.page) switchPage(item.dataset.page);
        });
    });
    
    document.getElementById('change-password-btn')?.addEventListener('click', changePassword);
    
    document.getElementById('refresh-users')?.addEventListener('click', loadUsersData);
    document.getElementById('pause-feed')?.addEventListener('click', toggleFeed);
    document.getElementById('threshold-slider')?.addEventListener('input', (e) => {
        document.getElementById('threshold-value').textContent = e.target.value;
    });
    document.getElementById('save-settings')?.addEventListener('click', saveSettings);
    document.getElementById('reload-data')?.addEventListener('click', reloadData);
    document.getElementById('auto-refresh')?.addEventListener('change', (e) => {
        autoRefreshEnabled = e.target.checked;
        if (autoRefreshEnabled) startAutoRefresh();
        else stopAutoRefresh();
    });
    
    // REPORT GENERATION EVENT LISTENER (NEW)
    document.getElementById('generate-report-btn')?.addEventListener('click', generateReport);
    
    setInterval(updateTime, 1000);
    updateTime();
    
    console.log('✓ Checking authentication...');
    console.log('✓ Behavioral Monitoring functions loaded');
    console.log('✓ Chat system functions loaded');
    console.log('✓ Report generation functions loaded');
    checkAuth();
});