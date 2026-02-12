"""
🔴 REAL-TIME EVENT TRACKING WITH EMAIL ALERTS
==============================================

Tracks and logs all system events in real-time.
Sends email alerts for critical security events.

Events tracked:
- Logins (success/failed)
- After-hours logins
- Brute force attacks
- File access (normal/sensitive)
- Cumulative anomalies
- Suspicious chat messages
- Logouts
"""

from datetime import datetime
from collections import deque
import threading

# Import email alert system
try:
    from email_alerts import send_security_alert_async
    EMAIL_ALERTS_AVAILABLE = True
except ImportError:
    EMAIL_ALERTS_AVAILABLE = False
    print("⚠️  Email alerts not available. Install email_alerts.py to enable.")

# ============================================================================
# GLOBAL EVENT STORAGE
# ============================================================================

events_log = deque(maxlen=1000)  # Keep last 1000 events
events_lock = threading.Lock()

# Brute force tracking
failed_login_attempts = {}  # {username: [timestamps]}
BRUTE_FORCE_THRESHOLD = 3  # Failed attempts
BRUTE_FORCE_WINDOW = 300  # 5 minutes (in seconds)

# ============================================================================
# EVENT TRACKER INITIALIZATION
# ============================================================================

def init_event_tracker():
    """Initialize the event tracking system"""
    print("✓ Real-time event tracker initialized")
    return True

# ============================================================================
# CORE EVENT LOGGING
# ============================================================================

def log_event(event_type, username, details, ip_address=None, send_email=False, severity='MEDIUM'):
    """
    Log an event to the real-time feed
    
    Args:
        event_type (str): Type of event
        username (str): Username involved
        details (str): Event details
        ip_address (str, optional): IP address
        send_email (bool): Whether to send email alert
        severity (str): Severity level for email
    """
    with events_lock:
        event = {
            'type': event_type,
            'username': username,
            'details': details,
            'ip_address': ip_address or 'N/A',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'time': datetime.now().strftime('%H:%M:%S')
        }
        
        events_log.append(event)
        
        # Send email alert for critical events
        if send_email and EMAIL_ALERTS_AVAILABLE:
            send_security_alert_async(
                alert_type=event_type,
                username=username,
                details=details,
                severity=severity,
                ip_address=ip_address
            )
        
        return event

# ============================================================================
# LOGIN EVENT TRACKING
# ============================================================================

def log_login(username, ip_address, success=True):
    """
    Log a login attempt with brute force and after-hours detection
    
    Args:
        username (str): Username attempting login
        ip_address (str): IP address of login attempt
        success (bool): Whether login was successful
    """
    
    if success:
        # Check if after-hours
        current_hour = datetime.now().hour
        is_after_hours = current_hour < 8 or current_hour >= 18
        is_weekend = datetime.now().weekday() >= 5
        
        if is_after_hours or is_weekend:
            # After-hours login detected - SEND EMAIL
            day_type = "weekend" if is_weekend else "after-hours"
            log_event(
                'after_hours_login',
                username,
                f"Login detected during {day_type} at {datetime.now().strftime('%H:%M')}",
                ip_address,
                send_email=True,
                severity='HIGH'
            )
        else:
            # Normal login
            log_event('login', username, f"Successful login from {ip_address}", ip_address)
        
        # Clear failed attempts on successful login
        if username in failed_login_attempts:
            del failed_login_attempts[username]
    
    else:
        # Failed login - track for brute force detection
        current_time = datetime.now()
        
        if username not in failed_login_attempts:
            failed_login_attempts[username] = []
        
        # Add current failed attempt
        failed_login_attempts[username].append(current_time)
        
        # Remove old attempts outside the time window
        cutoff_time = current_time.timestamp() - BRUTE_FORCE_WINDOW
        failed_login_attempts[username] = [
            attempt for attempt in failed_login_attempts[username]
            if attempt.timestamp() > cutoff_time
        ]
        
        # Check for brute force
        attempt_count = len(failed_login_attempts[username])
        
        if attempt_count >= BRUTE_FORCE_THRESHOLD:
            # Brute force detected - SEND EMAIL
            log_event(
                'brute_force',
                username,
                f"🚨 BRUTE FORCE ATTACK: {attempt_count} failed login attempts detected from {ip_address}",
                ip_address,
                send_email=True,
                severity='CRITICAL'
            )
        else:
            # Regular failed login - SEND EMAIL after 2nd attempt
            send_email = attempt_count >= 2
            log_event(
                'failed_login',
                username,
                f"Failed login attempt #{attempt_count} from {ip_address}",
                ip_address,
                send_email=send_email,
                severity='MEDIUM' if attempt_count == 2 else 'LOW'
            )

# ============================================================================
# FILE ACCESS EVENT TRACKING
# ============================================================================

def log_file_access(username, filepath, action='read'):
    """
    Log file access with sensitive file detection
    
    Args:
        username (str): Username accessing file
        filepath (str): Path of file being accessed
        action (str): Action performed (read/write/delete)
    """
    
    # Check if file is sensitive
    sensitive_patterns = [
        '/confidential/', '/secret/', '/admin/', '/hr/',
        '/financial/', '/salary', '/payroll', 'passwords', 
        'credentials', '.env', 'config', 'private'
    ]
    
    is_sensitive = any(pattern.lower() in filepath.lower() for pattern in sensitive_patterns)
    
    if is_sensitive:
        # Sensitive file access - SEND EMAIL
        log_event(
            'sensitive_file',
            username,
            f"🔐 SENSITIVE FILE ACCESS: {filepath} ({action})",
            send_email=True,
            severity='CRITICAL'
        )
    else:
        # Normal file access - no email
        log_event('file_access', username, f"File {action}: {filepath}")

# ============================================================================
# CUMULATIVE ANOMALY EVENT
# ============================================================================

def log_cumulative_anomaly(username, total_files, baseline_files, anomaly_score):
    """
    Log cumulative anomaly detection - SEND EMAIL
    
    Args:
        username (str): Username with anomaly
        total_files (int): Total files accessed
        baseline_files (int): Normal baseline
        anomaly_score (float): Anomaly score
    """
    
    files_above = total_files - baseline_files
    deviation_percent = ((total_files - baseline_files) / baseline_files * 100) if baseline_files > 0 else 0
    
    log_event(
        'cumulative_anomaly',
        username,
        f"📊 CUMULATIVE ANOMALY: {total_files} files accessed ({files_above} above baseline of {baseline_files}). Deviation: {deviation_percent:.0f}%. Anomaly score: {anomaly_score:.2f}",
        send_email=True,
        severity='CRITICAL'
    )

# ============================================================================
# SUSPICIOUS CHAT MESSAGE EVENT
# ============================================================================

def log_suspicious_chat(username, message, risk_score, threat_category):
    """
    Log suspicious chat message detected by NLP - SEND EMAIL
    
    Args:
        username (str): Username who sent the message
        message (str): The suspicious message
        risk_score (float): NLP risk score
        threat_category (str): Category of threat
    """
    
    # Truncate message for display
    message_preview = message[:100] + '...' if len(message) > 100 else message
    
    log_event(
        'suspicious_chat',
        username,
        f"💬 SUSPICIOUS CHAT: [{threat_category.upper()}] Risk: {risk_score:.2f} - Message: \"{message_preview}\"",
        send_email=True,
        severity='HIGH'
    )

# ============================================================================
# LOGOUT EVENT
# ============================================================================

def log_logout(username):
    """Log user logout"""
    log_event('logout', username, f"User logged out")

# ============================================================================
# GET RECENT EVENTS
# ============================================================================

def get_recent_events(limit=50):
    """
    Get recent events from the log
    
    Args:
        limit (int): Maximum number of events to return
    
    Returns:
        list: Recent events
    """
    with events_lock:
        return list(events_log)[-limit:]

# ============================================================================
# INITIALIZATION
# ============================================================================

print("🔴 Real-time event tracker loaded with email alerts")
if EMAIL_ALERTS_AVAILABLE:
    print("   ✅ Email alerts enabled")
else:
    print("   ⚠️  Email alerts disabled (install email_alerts.py)")

init_event_tracker()