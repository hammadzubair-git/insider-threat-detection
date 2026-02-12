from flask import request, jsonify, session, send_from_directory, send_file
from functools import wraps
import pandas as pd
import pickle
import numpy as np
from datetime import datetime, timedelta
import os
import sys
import json

# Add parent directory to path so we can import behavioral_monitoring
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import automated AI behavioral monitoring
from behavioral_monitoring import behavioral_monitor

# Import cumulative anomaly tracker (persistent, never resets)
try:
    from cumulative_anomaly_tracker import cumulative_tracker
    CUMULATIVE_TRACKER_AVAILABLE = True
except ImportError:
    CUMULATIVE_TRACKER_AVAILABLE = False
    print("⚠️  Cumulative anomaly tracker not available")

# Import chat system
try:
    from chat_system import send_message, get_messages, get_messages_since, clear_chat_history
    CHAT_SYSTEM_AVAILABLE = True
except ImportError:
    CHAT_SYSTEM_AVAILABLE = False
    print("⚠️  Chat system not available")

# Import real-time event tracking
try:
    from realtime_events import init_event_tracker, log_login, log_logout, log_file_access, log_event, get_recent_events
    REALTIME_EVENTS_AVAILABLE = True
except ImportError:
    REALTIME_EVENTS_AVAILABLE = False
    print("⚠️  Real-time events not available")


# Import email alerts for critical events
try:
    from email_alerts import send_security_alert_async
    EMAIL_ALERTS_AVAILABLE = True
except ImportError:
    EMAIL_ALERTS_AVAILABLE = False
    print("⚠️  Email alerts not available")

# ============================================================================
# NLP INTENT DETECTION - INITIALIZATION WITH DETAILED DIAGNOSTICS
# ============================================================================
print("\n" + "="*70)
print("🔍 INITIALIZING NLP MALICIOUS INTENT DETECTION")
print("="*70)

try:
    from chat_intent_detector import ChatIntentDetector
    print("✅ chat_intent_detector module imported successfully")
    
    # Initialize NLP Intent Detector
    nlp_detector = ChatIntentDetector(model_type='naive_bayes')
    print("✅ ChatIntentDetector instance created")
    
    # Load trained model - FIXED PATH: Go up one folder from dashboard/
    model_path = '../models/chat_intent_model.pkl'
    print(f"📂 Looking for model at: {model_path}")
    
    # Get absolute path for debugging
    abs_path = os.path.abspath(model_path)
    print(f"📂 Absolute path: {abs_path}")
    
    if os.path.exists(model_path):
        nlp_detector.load_model(model_path)
        print("✅ NLP Intent Detector loaded successfully")
        NLP_DETECTOR_AVAILABLE = True
    else:
        print("⚠️  WARNING: No trained model found at", model_path)
        print(f"   Checked: {abs_path}")
        print("   Please run: python train_model.py")
        NLP_DETECTOR_AVAILABLE = False
        
except ImportError as e:
    print(f"❌ NLP Intent Detector not available (import error): {e}")
    NLP_DETECTOR_AVAILABLE = False
except Exception as e:
    print(f"❌ ERROR loading NLP detector: {e}")
    import traceback
    traceback.print_exc()
    NLP_DETECTOR_AVAILABLE = False

print("="*70)
print(f"🎯 FINAL STATUS: NLP_DETECTOR_AVAILABLE = {NLP_DETECTOR_AVAILABLE}")
if NLP_DETECTOR_AVAILABLE:
    print("✅ NLP will analyze all chat messages for malicious intent")
    print("✅ Suspicious messages will trigger alerts in admin live feed")
else:
    print("❌ NLP is DISABLED - chat messages will NOT be analyzed")
    print("❌ Install chat_intent_detector.py and run train_model.py to enable")
print("="*70 + "\n")

# ==================== CONFIGURATION ====================
DATA_PATH = '../data'
MODELS_PATH = '../models'
CREDENTIALS_FILE = os.path.join(DATA_PATH, 'credentials.csv')
STATIC_PATH = './static'

# Global cache for data and models
dashboard_data_cache = {}
dashboard_models_cache = {}

# ==================== HELPER FUNCTIONS ====================

def init_dashboard_credentials():
    """Initialize credentials CSV if it doesn't exist"""
    if not os.path.exists(CREDENTIALS_FILE):
        creds = pd.DataFrame({
            'username': ['admin', 'analyst', 'viewer', 'john_doe', 'jane_smith'],
            'password': ['admin123', 'analyst123', 'viewer123', 'user123', 'user123'],
            'role': ['admin', 'analyst', 'viewer', 'user', 'user']
        })
        os.makedirs(DATA_PATH, exist_ok=True)
        creds.to_csv(CREDENTIALS_FILE, index=False)
        print(f"✓ Created credentials file: {CREDENTIALS_FILE}")
    else:
        print(f"✓ Credentials file exists: {CREDENTIALS_FILE}")

def dashboard_login_required(f):
    """Authentication decorator for dashboard routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'dashboard_user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def load_csv_data(filename):
    """Safely load CSV file"""
    filepath = os.path.join(DATA_PATH, filename)
    try:
        if os.path.exists(filepath):
            df = pd.read_csv(filepath)
            print(f"✓ Dashboard loaded {filename}: {len(df)} rows")
            return df
        else:
            print(f"⚠ Dashboard: {filename} not found")
            return pd.DataFrame()
    except Exception as e:
        print(f"✗ Dashboard error loading {filename}: {e}")
        return pd.DataFrame()

def load_dashboard_data():
    """Load all CSV files into cache"""
    print("\n" + "="*50)
    print("Loading Dashboard Data...")
    print("="*50)
    
    files = {
        'anomaly_scores': 'anomaly_scores.csv',
        'merged_features': 'merged_features.csv',
        'emails': 'emails.csv',
        'file_access': 'file_access.csv',
        'logins': 'logins.csv',
        'nlp_email_features': 'nlp_email_features.csv',
        'red_team_users': 'red_team_users.csv',
        'usb_usage': 'usb_usage.csv',
        'graph_features': 'graph_features.csv'
    }
    
    for key, filename in files.items():
        dashboard_data_cache[key] = load_csv_data(filename)
    
    print("="*50 + "\n")

def load_dashboard_models():
    """Load all ML models into cache"""
    print("\n" + "="*50)
    print("Loading Dashboard Models...")
    print("="*50)
    print("⚠ Models are in binary format (not pickle)")
    print("  Dashboard will work without models for display purposes")
    print("Skipping model loading - using data from CSV files only")
    print("="*50 + "\n")

# ============================================================================
# DATABASE FUNCTIONS FOR NLP INTENT ALERTS
# ============================================================================

def save_intent_alert(username, message, risk_score, severity, threat_category, confidence):
    """Save NLP intent alert to database"""
    import sqlite3
    
    try:
        # Create data directory if it doesn't exist
        os.makedirs('../data', exist_ok=True)
        
        conn = sqlite3.connect('../data/dashboard.db')
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS chat_intent_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                risk_score REAL NOT NULL,
                severity TEXT NOT NULL,
                threat_category TEXT,
                confidence REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Insert alert
        cursor.execute('''
            INSERT INTO chat_intent_alerts 
            (username, message, risk_score, severity, threat_category, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, message, risk_score, severity, threat_category, confidence))
        
        conn.commit()
        conn.close()
        
        print(f"✅ NLP Intent alert saved to database for {username}")
        return True
        
    except Exception as e:
        print(f"❌ Error saving intent alert to database: {e}")
        return False

# ==================== REGISTER ALL ROUTES ====================

def register_dashboard_routes(app):
    """Register all dashboard routes to Flask app"""
    
    # =====================================================================
    # REPORT GENERATION - Initialize report generator
    # =====================================================================
    
    from report_generator import UserReportGenerator
    
    # Initialize report generator
    try:
        report_generator = UserReportGenerator(data_path='../data')
        REPORT_GENERATOR_AVAILABLE = True
        print("✓ Report generator initialized")
    except Exception as e:
        print(f"⚠️  Report generator not available: {e}")
        REPORT_GENERATOR_AVAILABLE = False
    
    # Initialize data on first import
    init_dashboard_credentials()
    load_dashboard_data()
    load_dashboard_models()
    
    # Initialize real-time event tracker
    if REALTIME_EVENTS_AVAILABLE:
        init_event_tracker()
        print("✓ Real-time event tracker initialized")
    
    # ==================== AUTHENTICATION ====================
    
    @app.route('/dashboard/api/login', methods=['POST'])
    def dashboard_login():
        """Dashboard login endpoint with AUTOMATED AI detection"""
        try:
            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            ip_address = request.remote_addr
            
            print(f"Login attempt - Username: {username} from {ip_address}")
            
            if not username or not password:
                return jsonify({'success': False, 'error': 'Username and password required'}), 400
            
            if not os.path.exists(CREDENTIALS_FILE):
                return jsonify({'success': False, 'error': 'Credentials file not found'}), 500
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            user = creds[creds['username'].str.strip() == username]
            
            if user.empty:
                # Log failed login - user doesn't exist
                if REALTIME_EVENTS_AVAILABLE:
                    log_login(username, ip_address, success=False)
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
            
            stored_password = str(user.iloc[0]['password']).strip()
            
            if stored_password == password:
                role = user.iloc[0]['role']
                
                # Log successful login (will check after-hours automatically)
                if REALTIME_EVENTS_AVAILABLE:
                    log_login(username, ip_address, success=True)
                
                # 🔥 AUTO-DETECT ML ANOMALY AFTER LOGIN (Historical profiling)
                ml_result = behavioral_monitor.auto_detect_after_login(username, ip_address)
                
                if ml_result.get('is_anomaly'):
                    print(f"🚨 ML ANOMALY DETECTED: {username} - Score: {ml_result.get('anomaly_score', 0):.3f}")
                
                # Set session
                session['dashboard_user'] = username
                session['dashboard_role'] = role
                
                print(f"✓ Login successful - User: {username}, Role: {role}")
                
                # Convert numpy types to Python types for JSON serialization
                is_anomaly = bool(ml_result.get('is_anomaly', False))
                anomaly_score = float(ml_result.get('anomaly_score', 0))
                
                return jsonify({
                    'success': True,
                    'username': username,
                    'role': role,
                    'ml_anomaly_detected': is_anomaly,
                    'anomaly_score': anomaly_score
                })
            else:
                # Log failed login - wrong password
                if REALTIME_EVENTS_AVAILABLE:
                    log_login(username, ip_address, success=False)
                return jsonify({'success': False, 'error': 'Invalid username or password'}), 401
                
        except Exception as e:
            print(f"Login error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/dashboard/api/logout', methods=['POST'])
    def dashboard_logout():
        """Dashboard logout endpoint"""
        username = session.get('dashboard_user')
        
        # Log real-time logout event
        if REALTIME_EVENTS_AVAILABLE and username:
            log_logout(username)
        
        session.pop('dashboard_user', None)
        session.pop('dashboard_role', None)
        return jsonify({'success': True})
    
    @app.route('/dashboard/api/signup', methods=['POST'])
    def dashboard_signup():
        """Dashboard signup endpoint"""
        try:
            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            role = data.get('role', 'viewer').strip()
            
            if not username or not password:
                return jsonify({'success': False, 'error': 'Username and password required'}), 400
            
            if len(password) < 6:
                return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            if username in creds['username'].values:
                return jsonify({'success': False, 'error': 'Username already exists'}), 400
            
            new_user = pd.DataFrame({
                'username': [username],
                'password': [password],
                'role': [role]
            })
            creds = pd.concat([creds, new_user], ignore_index=True)
            creds.to_csv(CREDENTIALS_FILE, index=False)
            
            return jsonify({'success': True, 'message': 'Account created successfully'})
                
        except Exception as e:
            print(f"Signup error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/dashboard/api/check-auth', methods=['GET'])
    def dashboard_check_auth():
        """Check if user is authenticated"""
        if 'dashboard_user' in session:
            return jsonify({
                'authenticated': True,
                'username': session['dashboard_user'],
                'role': session.get('dashboard_role', 'viewer')
            })
        return jsonify({'authenticated': False}), 401
    
    # ==================== USER-SPECIFIC ENDPOINTS ====================
    
    @app.route('/dashboard/api/user/personal-data', methods=['GET'])
    @dashboard_login_required
    def user_personal_data():
        """Get personal data for logged-in user"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            print(f"📊 Loading personal data for user: {username}")
            
            anomaly_df = dashboard_data_cache.get('anomaly_scores', pd.DataFrame())
            logins_df = dashboard_data_cache.get('logins', pd.DataFrame())
            file_access_df = dashboard_data_cache.get('file_access', pd.DataFrame())
            
            user_score = 0.0
            risk_level = "Low"
            
            if not anomaly_df.empty:
                score_column = None
                for col in ['anomaly_score', 'isolation_forest', 'oneclass_svm', 'autoencoder']:
                    if col in anomaly_df.columns:
                        score_column = col
                        break
                
                if score_column:
                    user_row = anomaly_df[anomaly_df['user'].astype(str).str.lower() == username.lower()] if 'user' in anomaly_df.columns else pd.DataFrame()
                    
                    if user_row.empty and 'user_id' in anomaly_df.columns:
                        user_row = anomaly_df[anomaly_df['user_id'].astype(str).str.lower() == username.lower()]
                    
                    if not user_row.empty:
                        user_score = float(user_row.iloc[0][score_column])
                        
                        if 'risk_level' in anomaly_df.columns:
                            risk_level = str(user_row.iloc[0]['risk_level'])
                        else:
                            if user_score > 0.8:
                                risk_level = "High"
                            elif user_score > 0.5:
                                risk_level = "Medium"
            
            user_logins = 0
            last_login = "N/A"
            last_ip = "N/A"
            
            if not logins_df.empty:
                user_login_rows = logins_df[logins_df['user'].astype(str).str.lower() == username.lower()] if 'user' in logins_df.columns else pd.DataFrame()
                
                if user_login_rows.empty and 'user_id' in logins_df.columns:
                    user_login_rows = logins_df[logins_df['user_id'].astype(str).str.lower() == username.lower()]
                
                user_logins = len(user_login_rows)
                
                if not user_login_rows.empty:
                    latest = user_login_rows.iloc[0]
                    last_login = str(latest.get('timestamp', latest.get('date', 'N/A')))
                    last_ip = str(latest.get('ip_address', latest.get('ip', 'N/A')))
            
            user_files = 0
            if not file_access_df.empty:
                user_file_rows = file_access_df[file_access_df['user'].astype(str).str.lower() == username.lower()] if 'user' in file_access_df.columns else pd.DataFrame()
                
                if user_file_rows.empty and 'user_id' in file_access_df.columns:
                    user_file_rows = file_access_df[file_access_df['user_id'].astype(str).str.lower() == username.lower()]
                
                user_files = len(user_file_rows)
            
            response_data = {
                'username': username,
                'anomalyScore': round(user_score, 3),
                'riskLevel': risk_level,
                'loginCount': int(user_logins),
                'fileCount': int(user_files),
                'lastLogin': last_login,
                'lastIP': last_ip,
                'alertCount': 0 if user_score < 0.7 else 1
            }
            
            return jsonify(response_data)
            
        except Exception as e:
            print(f"❌ User personal data error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/user/my-activity', methods=['GET'])
    @dashboard_login_required
    def user_my_activity():
        """Get activity logs for logged-in user only"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            logs = []
            
            logins_df = dashboard_data_cache.get('logins', pd.DataFrame())
            if not logins_df.empty:
                user_logins = logins_df[logins_df['user'].astype(str).str.lower() == username.lower()] if 'user' in logins_df.columns else pd.DataFrame()
                
                if user_logins.empty and 'user_id' in logins_df.columns:
                    user_logins = logins_df[logins_df['user_id'].astype(str).str.lower() == username.lower()]
                
                for _, row in user_logins.head(10).iterrows():
                    logs.append({
                        'action': 'Login',
                        'resource': str(row.get('ip_address', row.get('ip', 'Unknown IP'))),
                        'timestamp': str(row.get('timestamp', row.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))))
                    })
            
            file_access_df = dashboard_data_cache.get('file_access', pd.DataFrame())
            if not file_access_df.empty:
                user_files = file_access_df[file_access_df['user'].astype(str).str.lower() == username.lower()] if 'user' in file_access_df.columns else pd.DataFrame()
                
                if user_files.empty and 'user_id' in file_access_df.columns:
                    user_files = file_access_df[file_access_df['user_id'].astype(str).str.lower() == username.lower()]
                
                path_col = 'file_path' if 'file_path' in file_access_df.columns else 'filename'
                for _, row in user_files.head(10).iterrows():
                    logs.append({
                        'action': 'File Access',
                        'resource': str(row.get(path_col, 'Unknown')),
                        'timestamp': str(row.get('timestamp', row.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))))
                    })
            
            usb_df = dashboard_data_cache.get('usb_usage', pd.DataFrame())
            if not usb_df.empty:
                user_usb = usb_df[usb_df['user'].astype(str).str.lower() == username.lower()] if 'user' in usb_df.columns else pd.DataFrame()
                
                if user_usb.empty and 'user_id' in usb_df.columns:
                    user_usb = usb_df[usb_df['user_id'].astype(str).str.lower() == username.lower()]
                
                for _, row in user_usb.head(5).iterrows():
                    logs.append({
                        'action': 'USB Device',
                        'resource': f"Device_{row.get('device_id', 'Unknown')}",
                        'timestamp': str(row.get('timestamp', row.get('date', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))))
                    })
            
            return jsonify(logs[:20])
            
        except Exception as e:
            print(f"❌ User activity error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/user/my-alerts', methods=['GET'])
    @dashboard_login_required
    def user_my_alerts():
        """Get security alerts for logged-in user only"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            alerts = []
            
            anomaly_df = dashboard_data_cache.get('anomaly_scores', pd.DataFrame())
            if not anomaly_df.empty:
                score_column = None
                for col in ['anomaly_score', 'isolation_forest', 'oneclass_svm']:
                    if col in anomaly_df.columns:
                        score_column = col
                        break
                
                if score_column:
                    user_row = anomaly_df[anomaly_df['user'].astype(str).str.lower() == username.lower()] if 'user' in anomaly_df.columns else pd.DataFrame()
                    
                    if user_row.empty and 'user_id' in anomaly_df.columns:
                        user_row = anomaly_df[anomaly_df['user_id'].astype(str).str.lower() == username.lower()]
                    
                    if not user_row.empty:
                        score = float(user_row.iloc[0][score_column])
                        if score > 0.7:
                            alerts.append({
                                'type': 'Elevated Anomaly Score',
                                'details': f'Your activity score is {score:.2f}, which is above normal',
                                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'status': 'Active'
                            })
            
            if len(alerts) == 0:
                alerts.append({
                    'type': 'All Clear',
                    'details': 'No security concerns detected',
                    'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'status': 'Normal'
                })
            
            return jsonify(alerts)
            
        except Exception as e:
            print(f"❌ User alerts error: {e}")
            return jsonify({'error': str(e)}), 500
    
    # ==================== PASSWORD CHANGE ENDPOINT ====================
    
    @app.route('/dashboard/api/change-password', methods=['POST'])
    @dashboard_login_required
    def change_password():
        """Change user password"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            data = request.json
            current_password = data.get('currentPassword', '').strip()
            new_password = data.get('newPassword', '').strip()
            
            if not current_password or not new_password:
                return jsonify({'success': False, 'error': 'Both passwords are required'}), 400
            
            if len(new_password) < 6:
                return jsonify({'success': False, 'error': 'Password must be at least 6 characters'}), 400
            
            if not os.path.exists(CREDENTIALS_FILE):
                return jsonify({'success': False, 'error': 'Credentials file not found'}), 500
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            user_row = creds[creds['username'].str.strip() == username]
            
            if user_row.empty:
                return jsonify({'success': False, 'error': 'User not found'}), 404
            
            stored_password = str(user_row.iloc[0]['password']).strip()
            if stored_password != current_password:
                return jsonify({'success': False, 'error': 'Current password is incorrect'}), 401
            
            creds.loc[creds['username'].str.strip() == username, 'password'] = new_password
            creds.to_csv(CREDENTIALS_FILE, index=False)
            
            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            })
            
        except Exception as e:
            print(f"❌ Password change error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # ==================== ADMIN ENDPOINTS ====================
    
    @app.route('/dashboard/api/admin/monitoring', methods=['GET'])
    @dashboard_login_required
    def admin_monitoring():
        """Get admin monitoring data"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            total_users = len(creds)
            
            anomaly_df = dashboard_data_cache.get('anomaly_scores', pd.DataFrame())
            
            critical_alerts = []
            if not anomaly_df.empty:
                score_column = 'anomaly_score' if 'anomaly_score' in anomaly_df.columns else 'isolation_forest'
                if score_column in anomaly_df.columns:
                    critical = anomaly_df[anomaly_df[score_column] > 0.9]
                    for _, row in critical.head(10).iterrows():
                        user = str(row.get('user', row.get('user_id', 'unknown')))
                        critical_alerts.append({
                            'user': user,
                            'type': 'Critical Anomaly Detected',
                            'severity': 'Critical',
                            'time': datetime.now().strftime('%H:%M:%S')
                        })
            
            return jsonify({
                'totalUsers': total_users,
                'activeSessions': 1,
                'activeThreats': len(critical_alerts),
                'eventsToday': len(anomaly_df) if not anomaly_df.empty else 0,
                'criticalAlerts': critical_alerts
            })
        except Exception as e:
            print(f"Admin monitoring error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/admin/live-feed', methods=['GET'])
    @dashboard_login_required
    def admin_live_feed():
        """Get live activity feed for admin"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            events = []
            
            if REALTIME_EVENTS_AVAILABLE:
                realtime_events = get_recent_events(limit=20)
                for rt_event in realtime_events:
                    event_type = rt_event['type']
                    
                    # Regular login
                    if event_type == 'login':
                        events.append({
                            'type': 'success',
                            'title': f"Login: {rt_event['username']}",
                            'details': rt_event.get('details', f"IP: {rt_event['ip_address']}"),
                            'time': rt_event['timestamp']
                        })
                    # After-hours login (WARNING)
                    elif event_type == 'after_hours_login':
                        events.append({
                            'type': 'warning',
                            'title': f"After-Hours Login: {rt_event['username']}",
                            'details': rt_event.get('details', 'Login outside office hours'),
                            'time': rt_event['timestamp']
                        })
                    # Brute force attack (CRITICAL)
                    elif event_type == 'brute_force':
                        events.append({
                            'type': 'danger',
                            'title': f"BRUTE FORCE: {rt_event['username']}",
                            'details': rt_event.get('details', 'Multiple failed login attempts detected'),
                            'time': rt_event['timestamp']
                        })
                    # Failed login attempts
                    elif event_type == 'failed_login':
                        events.append({
                            'type': 'warning',
                            'title': f"Failed Login: {rt_event['username']}",
                            'details': rt_event.get('details', 'Login attempt failed'),
                            'time': rt_event['timestamp']
                        })
                    # Sensitive file access (CRITICAL)
                    elif event_type == 'sensitive_file':
                        events.append({
                            'type': 'danger',
                            'title': f"SENSITIVE FILE: {rt_event['username']}",
                            'details': rt_event.get('details', 'Accessed sensitive file'),
                            'time': rt_event['timestamp']
                        })
                    # Cumulative anomaly (CRITICAL - Persistent tracking!)
                    elif event_type == 'cumulative_anomaly':
                        events.append({
                            'type': 'danger',
                            'title': f"🚨 CUMULATIVE ANOMALY: {rt_event['username']}",
                            'details': rt_event.get('details', 'Excessive cumulative file access detected'),
                            'time': rt_event['timestamp']
                        })
                    # Suspicious chat (NLP detection!) - THIS IS THE KEY ONE!
                    elif event_type == 'suspicious_chat':
                        events.append({
                            'type': 'danger',
                            'title': f"🚨 SUSPICIOUS CHAT: {rt_event['username']}",
                            'details': rt_event.get('details', 'Malicious intent detected in chat'),
                            'time': rt_event['timestamp']
                        })
                    # Logout
                    elif event_type == 'logout':
                        events.append({
                            'type': 'info',
                            'title': f"Logout: {rt_event['username']}",
                            'details': "Session ended",
                            'time': rt_event['timestamp']
                        })
                    # Normal file access - DO NOT SHOW IN LIVE FEED
                    # elif event_type == 'file_access':
                    #     pass  # Commented out to reduce noise
                    
                    # Email
                    # elif event_type == 'email':
                    #     pass  # Commented out to reduce noise
                    
                    # USB
                    # elif event_type == 'usb':
                    #     pass  # Commented out to reduce noise
            
            return jsonify({'events': events})
        except Exception as e:
            print(f"Live feed error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'events': []}), 500
    
    @app.route('/dashboard/api/alerts', methods=['GET'])
    @dashboard_login_required
    def dashboard_alerts():
        """Get alerts"""
        try:
            anomaly_df = dashboard_data_cache.get('anomaly_scores', pd.DataFrame())
            alerts = []
            
            if not anomaly_df.empty:
                score_column = 'anomaly_score' if 'anomaly_score' in anomaly_df.columns else 'isolation_forest'
                if score_column in anomaly_df.columns:
                    high_scores = anomaly_df[anomaly_df[score_column] > 0.7].nlargest(15, score_column)
                    
                    for idx, row in high_scores.iterrows():
                        user = str(row.get('user', row.get('user_id', 'unknown')))
                        alerts.append({
                            'id': len(alerts) + 1,
                            'user': user,
                            'type': 'Anomaly Detected',
                            'score': round(float(row[score_column]), 3),
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'status': 'Active'
                        })
            
            return jsonify(alerts[:20])
        except Exception as e:
            print(f"Alerts error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/activity-logs', methods=['GET'])
    @dashboard_login_required
    def dashboard_activity_logs():
        """Get activity logs from REALTIME EVENTS ONLY (no CSV data)"""
        try:
            all_activities = []
            
            # Get ONLY realtime events (logins, logouts, file access, chat, etc.)
            if REALTIME_EVENTS_AVAILABLE:
                try:
                    recent_events = get_recent_events(limit=200)
                    for event in recent_events:
                        event_type = event.get('type', 'unknown')
                        action = event_type.replace('_', ' ').title()
                        
                        # Map event types to user-friendly names with icons
                        action_map = {
                            'Login': '🔐 Login',
                            'Logout': '👋 Logout',
                            'After Hours Login': '🌙 After-Hours Login',
                            'Brute Force': '🚨 Brute Force Attack',
                            'Failed Login': '⚠️ Failed Login',
                            'Sensitive File': '🔐 Sensitive File Access',
                            'File Access': '📄 File Access',
                            'Suspicious Chat': '💬 Suspicious Chat',
                            'Cumulative Anomaly': '📊 Cumulative Anomaly'
                        }
                        
                        action = action_map.get(action, action)
                        
                        activity = {
                            'user': event.get('username', 'Unknown'),
                            'action': action,
                            'resource': event.get('details', ''),
                            'timestamp': event.get('timestamp', '')
                        }
                        all_activities.append(activity)
                except Exception as e:
                    print(f"Error loading realtime events: {e}")
            else:
                # If realtime events not available, show a message
                all_activities.append({
                    'user': 'System',
                    'action': 'ℹ️ Info',
                    'resource': 'Realtime event tracking is not available. Enable realtime_events.py to see live activities.',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
            
            # Remove duplicates based on user+action+timestamp
            seen = set()
            unique_activities = []
            for activity in all_activities:
                key = f"{activity['user']}_{activity['action']}_{activity['timestamp']}"
                if key not in seen:
                    seen.add(key)
                    unique_activities.append(activity)
            
            # Sort by timestamp (newest first)
            try:
                unique_activities.sort(
                    key=lambda x: x['timestamp'] if x['timestamp'] else '', 
                    reverse=True
                )
            except:
                pass  # If sorting fails, keep original order
            
            # Return top 100
            return jsonify(unique_activities[:100])
            
        except Exception as e:
            print(f"Activity logs error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify([])
    @app.route('/dashboard/api/security-logs', methods=['GET'])
    @dashboard_login_required
    def dashboard_security_logs():
        """Get security logs"""
        try:
            logs = []
            logs.append({
                'id': 1,
                'event': 'System Started',
                'severity': 'Info',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            return jsonify(logs)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/users', methods=['GET'])
    @dashboard_login_required
    def dashboard_get_users():
        """Get all users (admin only)"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            users = []
            for _, row in creds.iterrows():
                users.append({
                    'username': row['username'],
                    'role': row['role'],
                    'status': 'Active'
                })
            return jsonify(users)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/delete-user', methods=['POST'])
    @dashboard_login_required
    def dashboard_delete_user():
        """Delete a user (admin only)"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            data = request.json
            username = data.get('username')
            
            if username == 'admin':
                return jsonify({'success': False, 'error': 'Cannot delete admin'}), 400
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            creds = creds[creds['username'] != username]
            creds.to_csv(CREDENTIALS_FILE, index=False)
            
            return jsonify({'success': True})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/dashboard/api/settings', methods=['GET', 'POST'])
    @dashboard_login_required
    def dashboard_settings():
        """Get or update settings"""
        if request.method == 'GET':
            return jsonify({
                'anomalyThreshold': 0.7,
                'autoRefresh': True,
                'refreshInterval': 5,
                'modelsLoaded': [],
                'dataFilesLoaded': list(dashboard_data_cache.keys())
            })
        else:
            return jsonify({'success': True})
    
    @app.route('/dashboard/api/reload', methods=['POST'])
    @dashboard_login_required
    def dashboard_reload():
        """Reload data"""
        try:
            load_dashboard_data()
            return jsonify({
                'success': True,
                'dataFiles': len(dashboard_data_cache),
                'models': 0
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # =====================================================================
    # BEHAVIORAL MONITORING API ENDPOINTS
    # =====================================================================
    
    @app.route('/dashboard/api/behavioral/comprehensive-analysis', methods=['GET'])
    @dashboard_login_required
    def behavioral_comprehensive_analysis():
        """Get comprehensive behavioral analysis (all 5 features)"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            # Import behavioral monitor from threat monitoring
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.run_behavioral_analysis()
            
            return jsonify({
                'success': True,
                'analysis': results
            })
            
        except Exception as e:
            print(f"Behavioral analysis error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/behavioral/after-hours', methods=['GET'])
    @dashboard_login_required
    def behavioral_after_hours():
        """Get after-hours login detections"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.behavioral_monitor.detect_after_hours_logins()
            
            return jsonify({
                'success': True,
                'alerts': results.to_dict('records') if not results.empty else []
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/behavioral/sensitive-files', methods=['GET'])
    @dashboard_login_required
    def behavioral_sensitive_files():
        """Get sensitive file access detections"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.behavioral_monitor.detect_sensitive_file_access()
            
            return jsonify({
                'success': True,
                'alerts': results.to_dict('records') if not results.empty else []
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/behavioral/abnormal-logins', methods=['GET'])
    @dashboard_login_required
    def behavioral_abnormal_logins():
        """Get abnormal login behavior detections"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.behavioral_monitor.detect_abnormal_login_behavior()
            
            return jsonify({
                'success': True,
                'alerts': results.to_dict('records') if not results.empty else []
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/behavioral/unusual-activity', methods=['GET'])
    @dashboard_login_required
    def behavioral_unusual_activity():
        """Get unusual user activity detections"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.behavioral_monitor.detect_unusual_activity()
            
            return jsonify({
                'success': True,
                'alerts': results.to_dict('records') if not results.empty else []
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/behavioral/ml-anomalies', methods=['GET'])
    @dashboard_login_required
    def behavioral_ml_anomalies():
        """Get ML-based behavioral anomalies"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            from threat_monitoring_integration import threat_monitor
            
            if threat_monitor is None:
                return jsonify({'error': 'Threat monitoring not initialized'}), 500
            
            results = threat_monitor.behavioral_monitor.detect_behavioral_anomalies()
            
            return jsonify({
                'success': True,
                'alerts': results.to_dict('records') if not results.empty else []
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    # =====================================================================
    # AUTOMATED AI ENDPOINTS
    # =====================================================================
    
    @app.route('/dashboard/api/ml-status', methods=['GET'])
    @dashboard_login_required
    def ml_status():
        """Get ML model status"""
        try:
            status = behavioral_monitor.get_model_status()
            return jsonify(status)
        except Exception as e:
            print(f"ML status error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/user-risk-score', methods=['GET'])
    @dashboard_login_required
    def user_risk_score():
        """Get risk score for current user"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            risk_data = behavioral_monitor.get_user_risk_score(username)
            return jsonify(risk_data)
        except Exception as e:
            print(f"User risk score error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/cumulative-status', methods=['GET'])
    @dashboard_login_required
    def cumulative_status():
        """Get cumulative anomaly status for current user"""
        try:
            username = session.get('dashboard_user')
            if not username:
                return jsonify({'error': 'Not authenticated'}), 401
            
            if not CUMULATIVE_TRACKER_AVAILABLE:
                return jsonify({'error': 'Cumulative tracker not available'}), 503
            
            status = cumulative_tracker.get_user_status(username)
            if not status:
                return jsonify({
                    'active': False,
                    'message': 'No cumulative data'
                })
            
            return jsonify(status)
        except Exception as e:
            print(f"Cumulative status error: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =====================================================================
    # CHAT SYSTEM - Real-time messaging with NLP Intent Detection
    # =====================================================================
    
    @app.route('/dashboard/api/chat/messages', methods=['GET'])
    @dashboard_login_required
    def get_chat_messages():
        """Get recent chat messages"""
        try:
            if not CHAT_SYSTEM_AVAILABLE:
                return jsonify({'error': 'Chat system not available'}), 503
            
            limit = int(request.args.get('limit', 100))
            messages = get_messages(limit)
            
            return jsonify({
                'success': True,
                'messages': messages,
                'count': len(messages)
            })
        except Exception as e:
            print(f"Get messages error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/chat/send', methods=['POST'])
    @dashboard_login_required
    def send_chat_message():
        """Send a chat message with NLP intent detection"""
        
        # DIAGNOSTIC OUTPUT - ALWAYS SHOWS
        print("\n" + "🔴"*35)
        print("🔴 CHAT SEND ENDPOINT CALLED!")
        print("🔴"*35)
        
        try:
            if not CHAT_SYSTEM_AVAILABLE:
                print("❌ Chat system not available")
                return jsonify({'error': 'Chat system not available'}), 503
            
            data = request.json
            message = data.get('message', '').strip()
            
            if not message:
                return jsonify({'error': 'Message cannot be empty'}), 400
            
            if len(message) > 1000:
                return jsonify({'error': 'Message too long (max 1000 chars)'}), 400
            
            username = session.get('dashboard_user')
            role = session.get('dashboard_role', 'user')
            
            print(f"\n{'='*70}")
            print(f"📨 CHAT MESSAGE RECEIVED")
            print(f"{'='*70}")
            print(f"👤 User: {username}")
            print(f"🎭 Role: {role}")
            print(f"💬 Message: {message}")
            print(f"{'='*70}")
            
            # ================================================================
            # STEP 1: Send message to chat system
            # ================================================================
            msg_obj = send_message(username, message, role)
            print(f"✅ Message saved to chat system (ID: {msg_obj.get('id', 'N/A')})")
            
            # ================================================================
            # STEP 2: NLP INTENT DETECTION
            # ================================================================
            print(f"\n🔍 NLP ANALYSIS STARTING...")
            print(f"   NLP Detector Available: {NLP_DETECTOR_AVAILABLE}")
            
            if NLP_DETECTOR_AVAILABLE:
                try:
                    print(f"   📊 Analyzing message with NLP detector...")
                    
                    # Analyze message for malicious intent
                    analysis = nlp_detector.analyze_message(
                        message=message,
                        username=username
                    )
                    
                    print(f"\n📊 NLP ANALYSIS RESULTS:")
                    print(f"   ├─ Suspicious: {analysis['is_suspicious']}")
                    print(f"   ├─ Risk Score: {analysis['risk_score']:.3f}")
                    print(f"   ├─ Severity: {analysis['severity']}")
                    print(f"   ├─ Confidence: {analysis['confidence']:.3f}")
                    print(f"   └─ Category: {analysis.get('threat_category', 'N/A')}")
                    
                    # ========================================================
                    # ONLY LOG SUSPICIOUS MESSAGES TO LIVE FEED
                    # ========================================================
                    if nlp_detector.should_alert(analysis):
                        print(f"\n🚨🚨🚨 SUSPICIOUS MESSAGE DETECTED!")
                        print(f"   Severity: {analysis['severity']}")
                        print(f"   Risk Score: {analysis['risk_score']:.3f}")
                        print(f"   Generating alert for admin...")
                        
                        # Save alert to database
                        saved = save_intent_alert(
                            username=username,
                            message=message,
                            risk_score=analysis['risk_score'],
                            severity=analysis['severity'],
                            threat_category=analysis.get('threat_category', 'Unknown'),
                            confidence=analysis['confidence']
                        )
                        
                        if saved:
                            print(f"   ✅ Alert saved to database")
                        else:
                            print(f"   ⚠️  Failed to save alert to database")
                        
                        # Log to live feed (admin sees immediately)
                        if REALTIME_EVENTS_AVAILABLE:
                            category = analysis.get('threat_category', 'unknown').upper()
                            alert_message = f"🚨 [{category}] {message[:50]}{'...' if len(message) > 50 else ''}"
                            
                            log_event(
                                event_type='suspicious_chat',
                                username=username,
                                details=alert_message,
                                ip_address=request.remote_addr
                            )
                            
                            print(f"   ✅ Alert logged to LIVE FEED!")
                            print(f"   ✅ Admin will see: {alert_message}")
                        else:
                            print(f"   ⚠️  Real-time events not available - cannot log to live feed")
                        
                        # ========================================================
                        # SEND EMAIL ALERT FOR SUSPICIOUS MESSAGES
                        # ========================================================
                        if EMAIL_ALERTS_AVAILABLE and analysis['severity'] in ['HIGH', 'CRITICAL']:
                            try:
                                print(f"\n📧 SENDING EMAIL ALERT...")
                                email_sent = send_security_alert_async(
                                    alert_type='suspicious_chat',
                                    username=username,
                                    details=f"💬 SUSPICIOUS CHAT: [{category}] Risk: {analysis['risk_score']:.2f} - Message: {message[:100]}{'...' if len(message) > 100 else ''}",
                                    severity=analysis['severity'],
                                    ip_address=request.remote_addr
                                )
                                if email_sent:
                                    print(f"   ✅ EMAIL ALERT SENT to admin!")
                                else:
                                    print(f"   ⚠️  Email alert failed (check configuration)")
                            except Exception as email_error:
                                print(f"   ❌ Email error: {email_error}")
                        else:
                            if not EMAIL_ALERTS_AVAILABLE:
                                print(f"   ℹ️  Email alerts not available")
                            elif analysis['severity'] not in ['HIGH', 'CRITICAL']:
                                print(f"   ℹ️  No email for {analysis['severity']} severity")
                    else:
                        print(f"\n✅ Message is NORMAL - No alert generated")
                        print(f"   Risk score {analysis['risk_score']:.3f} < threshold (0.4)")
                        print(f"   Severity: {analysis['severity']}")
                
                except Exception as nlp_error:
                    print(f"\n❌ NLP ANALYSIS ERROR:")
                    print(f"   {str(nlp_error)}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"   ⚠️  NLP Detector NOT AVAILABLE")
                print(f"   ⚠️  Messages will NOT be analyzed")
                print(f"   ⚠️  Install chat_intent_detector.py and train model to enable")
            
            print(f"{'='*70}\n")
            
            # ================================================================
            # STEP 3: Return success
            # ================================================================
            return jsonify({
                'success': True,
                'message': msg_obj
            })
            
        except Exception as e:
            print(f"\n❌ CHAT SEND ERROR: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/chat/poll', methods=['GET'])
    @dashboard_login_required
    def poll_chat_messages():
        """Poll for new messages (for real-time updates)"""
        try:
            if not CHAT_SYSTEM_AVAILABLE:
                return jsonify({'error': 'Chat system not available'}), 503
            
            last_id = int(request.args.get('last_id', 0))
            new_messages = get_messages_since(last_id)
            
            return jsonify({
                'success': True,
                'messages': new_messages,
                'count': len(new_messages)
            })
        except Exception as e:
            print(f"Poll messages error: {e}")
            return jsonify({'error': str(e)}), 500
    
    @app.route('/dashboard/api/chat/clear', methods=['POST'])
    @dashboard_login_required
    def clear_chat():
        """Clear chat history (admin only)"""
        try:
            if not CHAT_SYSTEM_AVAILABLE:
                return jsonify({'error': 'Chat system not available'}), 503
            
            role = session.get('dashboard_role')
            if role != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            clear_chat_history()
            
            return jsonify({
                'success': True,
                'message': 'Chat history cleared'
            })
        except Exception as e:
            print(f"Clear chat error: {e}")
            return jsonify({'error': str(e)}), 500
    
    # =====================================================================
    # NLP INTENT ALERTS - Admin endpoints
    # =====================================================================
    
    @app.route('/dashboard/api/admin/intent-alerts', methods=['GET'])
    @dashboard_login_required
    def get_intent_alerts():
        """Get NLP intent detection alerts (admin only)"""
        import sqlite3
        
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Access denied'}), 403
            
            conn = sqlite3.connect('../data/dashboard.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM chat_intent_alerts 
                ORDER BY timestamp DESC 
                LIMIT 50
            ''')
            
            rows = cursor.fetchall()
            
            alerts = []
            for row in rows:
                alerts.append({
                    'id': row['id'],
                    'username': row['username'],
                    'message': row['message'],
                    'risk_score': row['risk_score'],
                    'severity': row['severity'],
                    'threat_category': row['threat_category'],
                    'confidence': row['confidence'],
                    'timestamp': row['timestamp'],
                    'status': row['status']
                })
            
            conn.close()
            
            return jsonify({'success': True, 'alerts': alerts})
        
        except Exception as e:
            print(f"Get intent alerts error: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # =====================================================================
    # FILE SIMULATOR FOR DEMO
    # =====================================================================
    
    @app.route('/dashboard/api/simulate-file-access', methods=['POST'])
    @dashboard_login_required
    def simulate_file_access():
        """Simulate file access with AUTOMATED AI detection"""
        try:
            data = request.json
            filepath = data.get('filepath', '')
            action = data.get('action', 'read')
            
            username = session.get('dashboard_user')
            
            if not filepath:
                return jsonify({'success': False, 'error': 'Filepath required'}), 400
            
            # Check if file is sensitive
            is_sensitive = any(pattern.lower() in filepath.lower() 
                             for pattern in ['/confidential/', '/secret/', '/admin/', '/hr/',
                                           '/financial/', '/salary', '/payroll', 'passwords', 'credentials'])
            
            # 🔥 CUMULATIVE ANOMALY TRACKING (Persistent - Never Resets!)
            cumulative_result = {'is_anomaly': False}
            if CUMULATIVE_TRACKER_AVAILABLE:
                cumulative_result = cumulative_tracker.on_file_access(username, filepath, is_sensitive)
                
                # Only log CRITICAL alerts to live feed (not warning/high)
                if cumulative_result.get('severity') == 'CRITICAL':
                    stats = cumulative_result.get('cumulative_stats', {})
                    print(f"\n🚨🚨🚨 CRITICAL CUMULATIVE ANOMALY: {username}")
                    print(f"   Total files: {stats.get('total_files', 0)}")
                    print(f"   Baseline: {stats.get('baseline_files', 0)}")
                    print(f"   Files above baseline: {stats.get('total_files', 0) - stats.get('baseline_files', 0)}")
                    print(f"   Deviation: {stats.get('deviation_percent', 0):.0f}% above normal")
                    print(f"   Anomaly Score: {cumulative_result.get('anomaly_score', 0):.2f}")
                    
                    # Log CRITICAL alert to realtime events (shows in live feed!)
                    if REALTIME_EVENTS_AVAILABLE:
                        files_above = stats.get('total_files', 0) - stats.get('baseline_files', 0)
                        alert_details = (f"🚨 CRITICAL: {stats.get('total_files', 0)} files accessed "
                                       f"({files_above} above baseline of {stats.get('baseline_files', 0)}). "
                                       f"Anomaly score: {cumulative_result.get('anomaly_score', 0):.2f}")
                        log_event('cumulative_anomaly', username, alert_details, request.remote_addr)
            
            # 🔥 HISTORICAL ML ANOMALY DETECTION (existing)
            ml_result = behavioral_monitor.auto_detect_after_file_access(
                username=username,
                filepath=filepath,
                action=action
            )
            
            # Log file access event (will detect sensitive files automatically)
            if REALTIME_EVENTS_AVAILABLE:
                log_file_access(username, filepath, action)
            
            # Log if high risk detected
            if ml_result.get('overall_risk') == 'HIGH':
                print(f"🚨 HIGH RISK FILE ACCESS: {username} accessed {filepath}")
                print(f"   Sensitive: {ml_result.get('is_sensitive')}, ML Anomaly: {ml_result.get('ml_anomaly')}")
            
            # Convert any numpy types to Python types for JSON serialization
            safe_ml_result = {
                'user': str(ml_result.get('user', username)),
                'filepath': str(ml_result.get('filepath', filepath)),
                'is_sensitive': bool(ml_result.get('is_sensitive', False)),
                'ml_anomaly': bool(ml_result.get('ml_anomaly', False)),
                'anomaly_score': float(ml_result.get('anomaly_score', 0)),
                'overall_risk': str(ml_result.get('overall_risk', 'LOW'))
            }
            
            return jsonify({
                'success': True,
                'message': f'File accessed: {filepath}',
                'filepath': filepath,
                'action': action,
                'ml_result': safe_ml_result,
                'cumulative_anomaly': {
                    'detected': cumulative_result.get('is_anomaly', False),
                    'severity': cumulative_result.get('severity', 'LOW'),
                    'anomaly_score': cumulative_result.get('anomaly_score', 0),
                    'cumulative_stats': cumulative_result.get('cumulative_stats', {}),
                    'thresholds': cumulative_result.get('thresholds', {})
                }
            })
            
        except Exception as e:
            print(f"File simulator error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # =====================================================================
    # REPORT GENERATION ENDPOINTS (ADMIN ONLY)
    # =====================================================================
    
    @app.route('/dashboard/api/admin/generate-report', methods=['POST'])
    @dashboard_login_required
    def generate_user_report():
        """Generate comprehensive PDF report for a user (Admin only)"""
        try:
            # Check if admin
            if session.get('dashboard_role') != 'admin':
                return jsonify({'success': False, 'error': 'Admin access required'}), 403
            
            if not REPORT_GENERATOR_AVAILABLE:
                return jsonify({'success': False, 'error': 'Report generator not available'}), 503
            
            data = request.json
            username = data.get('username', '').strip()
            days = int(data.get('days', 30))
            
            if not username:
                return jsonify({'success': False, 'error': 'Username required'}), 400
            
            if days not in [7, 30, 90]:
                return jsonify({'success': False, 'error': 'Days must be 7, 30, or 90'}), 400
            
            print(f"\n{'='*70}")
            print(f"📊 GENERATING REPORT")
            print(f"{'='*70}")
            print(f"User: {username}")
            print(f"Period: Last {days} days")
            print(f"Requested by: {session.get('dashboard_user')}")
            print(f"{'='*70}\n")
            
            # Generate report
            report_path = report_generator.generate_report(username, days=days)
            
            # Return file for download
            return send_file(
                report_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=f'report_{username}_{datetime.now().strftime("%Y%m%d")}.pdf'
            )
            
        except Exception as e:
            print(f"❌ Report generation error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/dashboard/api/admin/available-users', methods=['GET'])
    @dashboard_login_required
    def get_available_users_for_report():
        """Get list of users for report generation"""
        try:
            if session.get('dashboard_role') != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
            
            creds = pd.read_csv(CREDENTIALS_FILE)
            users = creds['username'].tolist()
            
            return jsonify({
                'success': True,
                'users': users
            })
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    # ==================== SERVE FRONTEND ====================
    
    @app.route('/dashboard')
    @app.route('/dashboard/')
    def serve_dashboard():
        """Serve the dashboard HTML"""
        return send_from_directory(STATIC_PATH, 'index.html')
    
    @app.route('/dashboard/<path:path>')
    def serve_dashboard_static(path):
        """Serve dashboard static files"""
        return send_from_directory(STATIC_PATH, path)
    
    print("\n✅ Dashboard routes registered successfully!")
    print(f"   Dashboard URL: http://localhost:5000/dashboard")
    print(f"   User Login: john_doe / user123")
    print(f"   Admin Login: admin / admin123")
    print(f"   ✓ Behavioral Monitoring: 5 API endpoints")
    print(f"   ✓ Automated AI: 2 endpoints (ml-status, user-risk-score)")
    print(f"   ✓ Cumulative Tracking: CRITICAL alert at 15 files (NEVER resets!)")
    print(f"   ✓ Chat System: Real-time messaging for all users")
    print(f"   ✓ NLP Intent Detection: {'✅ ENABLED' if NLP_DETECTOR_AVAILABLE else '❌ DISABLED (run train_model.py)'}")
    print(f"   ✓ Real-time Events: Active with behavioral tracking")
    print(f"   ✓ File Simulator: Available with ML detection")
    print(f"   ✓ Report Generation: {'✅ AVAILABLE' if REPORT_GENERATOR_AVAILABLE else '❌ DISABLED (install reportlab)'}")
    print(f"   ✓ Auto-detect: Login + File Access + Cumulative + Chat Intent\n")