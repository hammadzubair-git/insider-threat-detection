"""
📧 ASYNC EMAIL ALERT SYSTEM (NON-BLOCKING)
===========================================

Sends email notifications in BACKGROUND THREADS so the main
application stays fast and responsive.

NO MORE SLOWNESS! Emails are sent asynchronously without blocking
the web requests.

Usage:
    from email_alerts_async import send_security_alert_async
    
    # This returns IMMEDIATELY, email sent in background
    send_security_alert_async(
        alert_type='brute_force',
        username='user11',
        details='5 failed login attempts detected',
        severity='CRITICAL'
    )
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import threading
import queue
import time

# ============================================================================
# EMAIL CONFIGURATION
# ============================================================================

# ADMIN EMAIL - Change this to your email address
ADMIN_EMAIL = "hammadmalik6081@gmail.com"  # ← CHANGE THIS!

# SMTP CONFIGURATION (Gmail example)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "hammadmalik6081@gmail.com"  # ← CHANGE THIS!
SMTP_PASSWORD = "irft tgzf tcjk idxa"     # ← CHANGE THIS! (Use App Password for Gmail)

# Enable/Disable email alerts
EMAIL_ALERTS_ENABLED = True  # Set to False to disable

# ============================================================================
# BACKGROUND EMAIL QUEUE
# ============================================================================

email_queue = queue.Queue()
email_worker_running = False
email_worker_thread = None
emails_sent_count = 0
emails_failed_count = 0

# ============================================================================
# EMAIL WORKER THREAD (RUNS IN BACKGROUND)
# ============================================================================

def email_worker():
    """
    Background worker that processes email queue
    Runs in a separate thread, doesn't block main application
    """
    global emails_sent_count, emails_failed_count
    
    print("📧 Email worker thread started (background)")
    
    while email_worker_running:
        try:
            # Get email from queue (wait max 1 second)
            email_data = email_queue.get(timeout=1)
            
            if email_data is None:  # Shutdown signal
                break
            
            # Send the email
            success = _send_email_sync(email_data)
            
            if success:
                emails_sent_count += 1
            else:
                emails_failed_count += 1
            
            email_queue.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            print(f"❌ Email worker error: {e}")
            emails_failed_count += 1
    
    print("📧 Email worker thread stopped")


def _send_email_sync(email_data):
    """
    Actually send the email (synchronous, but runs in background thread)
    
    Args:
        email_data (dict): Email data with alert_type, username, details, etc.
    
    Returns:
        bool: True if sent successfully
    """
    
    if not EMAIL_ALERTS_ENABLED:
        print(f"⚠️  Email alerts disabled. Skipping: {email_data['alert_type']}")
        return False
    
    # Validate configuration
    if ADMIN_EMAIL == "your_email@gmail.com" or SMTP_USERNAME == "your_email@gmail.com":
        print("⚠️  Email not configured. Update ADMIN_EMAIL and SMTP credentials")
        return False
    
    try:
        alert_type = email_data['alert_type']
        username = email_data['username']
        details = email_data['details']
        severity = email_data.get('severity', 'MEDIUM')
        ip_address = email_data.get('ip_address')
        
        # Create email
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 SECURITY ALERT: {alert_type.upper().replace('_', ' ')} - {username}"
        msg['From'] = SMTP_USERNAME
        msg['To'] = ADMIN_EMAIL
        
        # Alert type emoji mapping
        alert_emojis = {
            'brute_force': '🚨',
            'after_hours_login': '🌙',
            'sensitive_file': '🔐',
            'failed_login': '⚠️',
            'cumulative_anomaly': '📊',
            'suspicious_chat': '💬',
            'ml_anomaly': '🤖'
        }
        
        emoji = alert_emojis.get(alert_type, '⚠️')
        
        # Severity color
        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#f97316',
            'MEDIUM': '#f59e0b',
            'LOW': '#10b981'
        }
        severity_color = severity_colors.get(severity, '#6b7280')
        
        # HTML email body
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                    background-color: #f3f4f6;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: white;
                    border-radius: 12px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    margin: 0;
                    font-size: 28px;
                    font-weight: 600;
                }}
                .header p {{
                    margin: 10px 0 0 0;
                    opacity: 0.9;
                    font-size: 14px;
                }}
                .content {{
                    padding: 30px;
                }}
                .alert-box {{
                    background-color: #fef2f2;
                    border-left: 4px solid {severity_color};
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 20px;
                }}
                .alert-title {{
                    color: {severity_color};
                    font-size: 20px;
                    font-weight: 600;
                    margin: 0 0 10px 0;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: 120px 1fr;
                    gap: 12px;
                    margin-top: 20px;
                }}
                .info-label {{
                    color: #6b7280;
                    font-weight: 600;
                    font-size: 14px;
                }}
                .info-value {{
                    color: #1f2937;
                    font-size: 14px;
                }}
                .severity-badge {{
                    display: inline-block;
                    background-color: {severity_color};
                    color: white;
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                .footer {{
                    background-color: #f9fafb;
                    padding: 20px 30px;
                    text-align: center;
                    font-size: 12px;
                    color: #6b7280;
                    border-top: 1px solid #e5e7eb;
                }}
                .action-button {{
                    display: inline-block;
                    background-color: #3b82f6;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 8px;
                    margin-top: 20px;
                    font-weight: 600;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{emoji} Security Alert</h1>
                    <p>AI-Powered Insider Threat Detection System</p>
                </div>
                
                <div class="content">
                    <div class="alert-box">
                        <div class="alert-title">
                            {alert_type.upper().replace('_', ' ')}
                        </div>
                        <p style="margin: 10px 0 0 0; color: #374151; font-size: 15px;">
                            {details}
                        </p>
                    </div>
                    
                    <div class="info-grid">
                        <div class="info-label">User:</div>
                        <div class="info-value"><strong>{username}</strong></div>
                        
                        <div class="info-label">Severity:</div>
                        <div class="info-value"><span class="severity-badge">{severity}</span></div>
                        
                        <div class="info-label">Timestamp:</div>
                        <div class="info-value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                        
                        {f'<div class="info-label">IP Address:</div><div class="info-value">{ip_address}</div>' if ip_address else ''}
                        
                        <div class="info-label">Alert Type:</div>
                        <div class="info-value">{alert_type}</div>
                    </div>
                    
                    <div style="text-align: center;">
                        <a href="http://localhost:5000/dashboard" class="action-button">
                            View Dashboard
                        </a>
                    </div>
                </div>
                
                <div class="footer">
                    <p>This is an automated security alert from the Insider Threat Detection System.</p>
                    <p>Please investigate this incident immediately.</p>
                    <p style="margin-top: 10px; font-size: 11px;">
                        © 2024 AI-Powered Insider Threat Detection System
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version (fallback)
        text_body = f"""
SECURITY ALERT: {alert_type.upper().replace('_', ' ')}

{details}

User: {username}
Severity: {severity}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{f'IP Address: {ip_address}' if ip_address else ''}

Please investigate this incident immediately.
View Dashboard: http://localhost:5000/dashboard

---
This is an automated security alert from the Insider Threat Detection System.
        """
        
        # Attach both versions
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"✅ Email sent (background): {alert_type} for {username}")
        return True
        
    except Exception as e:
        print(f"❌ Email send failed (background): {e}")
        return False


# ============================================================================
# PUBLIC API - ASYNC EMAIL SENDING (NON-BLOCKING)
# ============================================================================

def send_security_alert_async(alert_type, username, details, severity='HIGH', ip_address=None):
    """
    Send security alert email ASYNCHRONOUSLY (non-blocking)
    
    This function returns IMMEDIATELY. The email is sent in a background thread.
    
    Args:
        alert_type (str): Type of alert (brute_force, after_hours_login, etc.)
        username (str): Username involved in the alert
        details (str): Detailed description of the alert
        severity (str): Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        ip_address (str, optional): IP address if relevant
    
    Returns:
        bool: True (always, since it's async - actual result is unknown)
    """
    
    global email_worker_running, email_worker_thread
    
    # Start worker thread if not running
    if not email_worker_running:
        start_email_worker()
    
    # Queue the email (returns immediately)
    email_data = {
        'alert_type': alert_type,
        'username': username,
        'details': details,
        'severity': severity,
        'ip_address': ip_address
    }
    
    email_queue.put(email_data)
    print(f"📧 Email queued (will send in background): {alert_type} for {username}")
    
    return True


def start_email_worker():
    """Start the background email worker thread"""
    global email_worker_running, email_worker_thread
    
    if email_worker_running:
        return
    
    email_worker_running = True
    email_worker_thread = threading.Thread(target=email_worker, daemon=True)
    email_worker_thread.start()
    
    print("✅ Async email worker started")


def stop_email_worker():
    """Stop the background email worker thread"""
    global email_worker_running
    
    if not email_worker_running:
        return
    
    email_worker_running = False
    email_queue.put(None)  # Shutdown signal
    
    if email_worker_thread:
        email_worker_thread.join(timeout=5)
    
    print("✅ Async email worker stopped")


def get_email_stats():
    """Get email sending statistics"""
    return {
        'sent': emails_sent_count,
        'failed': emails_failed_count,
        'queued': email_queue.qsize(),
        'worker_running': email_worker_running
    }


# ============================================================================
# BACKWARD COMPATIBILITY - Synchronous version (blocks, but kept for testing)
# ============================================================================

def send_security_alert(alert_type, username, details, severity='HIGH', ip_address=None):
    """
    DEPRECATED: Use send_security_alert_async() instead
    
    This is the old synchronous version that BLOCKS the request.
    Kept for backward compatibility and testing only.
    """
    print("⚠️  WARNING: Using SYNCHRONOUS email send (slow!)")
    print("⚠️  Use send_security_alert_async() for fast, non-blocking email")
    
    email_data = {
        'alert_type': alert_type,
        'username': username,
        'details': details,
        'severity': severity,
        'ip_address': ip_address
    }
    
    return _send_email_sync(email_data)


# ============================================================================
# AUTO-START EMAIL WORKER ON IMPORT
# ============================================================================

print("📧 Async email alerts module loaded")
start_email_worker()


# ============================================================================
# QUICK TEST FUNCTION
# ============================================================================

def test_async_email():
    """Test async email system"""
    print("\n" + "="*60)
    print("📧 TESTING ASYNC EMAIL ALERT SYSTEM")
    print("="*60)
    
    if not EMAIL_ALERTS_ENABLED:
        print("⚠️  Email alerts are disabled. Set EMAIL_ALERTS_ENABLED = True")
        return
    
    if ADMIN_EMAIL == "your_email@gmail.com":
        print("❌ Please configure ADMIN_EMAIL and SMTP settings first!")
        return
    
    print(f"\nSending test alert to: {ADMIN_EMAIL}")
    print("This should return IMMEDIATELY (non-blocking)...\n")
    
    start_time = time.time()
    
    send_security_alert_async(
        alert_type='test_alert',
        username='test_user',
        details='This is an ASYNC test email. The request should have returned instantly!',
        severity='MEDIUM',
        ip_address='192.168.1.100'
    )
    
    elapsed = time.time() - start_time
    
    print(f"\n✅ Function returned in {elapsed:.3f} seconds")
    print(f"   (Should be < 0.01 seconds if async is working)")
    print(f"\nEmail is being sent in background thread...")
    print(f"Check your inbox at: {ADMIN_EMAIL}")
    
    # Wait a bit and show stats
    time.sleep(3)
    stats = get_email_stats()
    print(f"\n📊 Email Stats:")
    print(f"   Sent: {stats['sent']}")
    print(f"   Failed: {stats['failed']}")
    print(f"   Queued: {stats['queued']}")
    
    print("="*60 + "\n")


if __name__ == "__main__":
    test_async_email()