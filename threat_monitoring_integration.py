import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nlp_log_analyzer import NLPLogAnalyzer
from email_alerter import EmailAlerter
from behavioral_monitoring import BehavioralMonitor  # NEW!
import pandas as pd
from datetime import datetime
from flask import Blueprint, jsonify, request
from functools import wraps
import threading
import time


class ThreatMonitor:
    """
    Integrated threat monitoring system with behavioral analysis
    """
    
    def __init__(self, data_path='../data', model_path='../models'):
        """
        Initialize Threat Monitor
        
        Args:
            data_path: Path to data directory
            model_path: Path to models directory
        """
        self.data_path = data_path
        self.model_path = model_path
        
        # Initialize components
        print("\n" + "="*70)
        print("🚀 INITIALIZING THREAT MONITORING SYSTEM")
        print("="*70 + "\n")
        
        # Initialize NLP Analyzer
        print("📝 Initializing NLP Log Analyzer...")
        self.nlp_analyzer = NLPLogAnalyzer(model_path=model_path, data_path=data_path)
        
        # Try to load existing models, train if not found
        if not self.nlp_analyzer.load_models():
            print("   Training new NLP models...")
            self.nlp_analyzer.train_model(save_model=True)
        
        # Initialize Email Alerter
        print("\n📧 Initializing Email Alerter...")
        self.email_alerter = EmailAlerter()
        
        # NEW: Initialize Behavioral Monitor
        print("\n🧠 Initializing Behavioral Monitor...")
        self.behavioral_monitor = BehavioralMonitor(data_path=data_path)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        self.last_check_time = None
        self.alerts_sent_today = 0
        
        print("\n" + "="*70)
        print("✅ THREAT MONITORING SYSTEM READY")
        print("   ✓ NLP Analysis")
        print("   ✓ Email Alerting")
        print("   ✓ Behavioral Monitoring (5 Features)")
        print("="*70 + "\n")
    
    def analyze_log_entry(self, log_text, send_alert=True):
        """
        Analyze a single log entry and send alert if suspicious
        
        Args:
            log_text: Log text to analyze
            send_alert: Whether to send email alert
            
        Returns:
            Analysis result dictionary
        """
        # Analyze with NLP
        result = self.nlp_analyzer.analyze_log(log_text)
        
        # Send alert if suspicious and high risk
        if send_alert and result['risk_level'] == 'HIGH':
            print(f"   ⚠️  HIGH RISK LOG DETECTED!")
            print(f"   Sending email alert...")
            self.email_alerter.send_suspicious_log_alert(result)
            self.alerts_sent_today += 1
        
        return result
    
    def check_after_hours_logins(self, logins_df=None, max_alerts=5):
        """
        Check for after-hours logins and send alerts
        
        Args:
            logins_df: DataFrame with login data
            max_alerts: Maximum number of email alerts to send (default: 5)
            
        Returns:
            Number of alerts sent
        """
        if logins_df is None:
            # Load from file
            logins_path = os.path.join(self.data_path, 'logins.csv')
            if not os.path.exists(logins_path):
                return 0
            logins_df = pd.read_csv(logins_path)
        
        alerts_sent = 0
        total_after_hours = 0
        
        # Check each login (but limit email alerts)
        for _, row in logins_df.iterrows():
            user = row.get('user', 'Unknown')
            timestamp = row.get('timestamp', '')
            ip_address = row.get('ip_address', 'Unknown')
            
            # Check if after hours
            if self.email_alerter.is_after_hours(timestamp):
                total_after_hours += 1
                
                # Only send email if we haven't hit the limit
                if alerts_sent < max_alerts:
                    print(f"   ⚠️  After-hours login detected: {user} at {timestamp}")
                    success = self.email_alerter.send_after_hours_alert(user, timestamp, ip_address)
                    if success:
                        alerts_sent += 1
                        self.alerts_sent_today += 1
        
        # Print summary
        if total_after_hours > 0:
            print(f"   ℹ️  Found {total_after_hours} after-hours logins, sent {alerts_sent} email alerts")
        
        return alerts_sent
    
    def check_high_risk_users(self, anomaly_scores_df=None, threshold=0.8):
        """
        Check for high-risk users and send alerts
        
        Args:
            anomaly_scores_df: DataFrame with anomaly scores
            threshold: Anomaly score threshold for alerts
            
        Returns:
            Number of alerts sent
        """
        if anomaly_scores_df is None:
            # Load from file
            scores_path = os.path.join(self.data_path, 'anomaly_scores.csv')
            if not os.path.exists(scores_path):
                return 0
            anomaly_scores_df = pd.read_csv(scores_path)
        
        # Get high-risk users
        high_risk = anomaly_scores_df[anomaly_scores_df['anomaly_score'] > threshold]
        
        alerts_sent = 0
        
        for _, row in high_risk.iterrows():
            user = row.get('user', 'Unknown')
            score = row.get('anomaly_score', 0)
            
            # Get user's recent activities (sample for demo)
            activities = [
                f"Anomaly score: {score:.3f}",
                "Multiple suspicious file accesses",
                "After-hours login attempts",
                "External data transfers"
            ]
            
            print(f"   ⚠️  High-risk user detected: {user} (score: {score:.3f})")
            success = self.email_alerter.send_high_risk_user_alert(user, score, activities)
            if success:
                alerts_sent += 1
                self.alerts_sent_today += 1
        
        return alerts_sent
    
    # =====================================================================
    # NEW: BEHAVIORAL MONITORING FUNCTIONS
    # =====================================================================
    
    def run_behavioral_analysis(self):
        """
        Run comprehensive behavioral analysis (all 5 features)
        
        Returns:
            Dictionary with analysis results
        """
        print("\n🧠 Running behavioral analysis...")
        results = self.behavioral_monitor.run_comprehensive_analysis()
        return results
    
    def check_sensitive_file_access(self):
        """
        Check for sensitive file access and send alerts
        
        Returns:
            Number of alerts sent
        """
        print("\n📂 Checking sensitive file access...")
        sensitive_df = self.behavioral_monitor.detect_sensitive_file_access()
        
        alerts_sent = 0
        
        # Send alerts for critical/high severity events
        for _, row in sensitive_df.iterrows():
            if row.get('severity') in ['Critical', 'High']:
                user = row.get('user', 'Unknown')
                file_path = row.get('file_path', 'Unknown')
                reason = row.get('reason', 'Sensitive file access')
                
                print(f"   ⚠️  Sensitive file access: {user} → {file_path}")
                
                # Create custom email for sensitive file access
                activities = [
                    f"File: {file_path}",
                    f"Action: {row.get('action', 'access')}",
                    f"Reason: {reason}",
                    f"User Risk: {row.get('user_risk_level', 'Unknown')}"
                ]
                
                success = self.email_alerter.send_high_risk_user_alert(
                    user, 
                    row.get('user_anomaly_score', 0.5),
                    activities
                )
                
                if success:
                    alerts_sent += 1
                    self.alerts_sent_today += 1
        
        return alerts_sent
    
    def check_abnormal_logins(self):
        """
        Check for abnormal login behavior
        
        Returns:
            Number of alerts sent
        """
        print("\n🔐 Checking abnormal login behavior...")
        abnormal_df = self.behavioral_monitor.detect_abnormal_login_behavior()
        
        alerts_sent = 0
        
        # Send alerts for high severity events
        for _, row in abnormal_df.iterrows():
            if row.get('severity') == 'High':
                user = row.get('user', 'Unknown')
                ip = row.get('ip_address', 'Unknown')
                reason = row.get('reason', 'Abnormal login')
                
                print(f"   ⚠️  Abnormal login: {user} from {ip}")
                
                success = self.email_alerter.send_after_hours_alert(
                    user,
                    row.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                    ip
                )
                
                if success:
                    alerts_sent += 1
                    self.alerts_sent_today += 1
        
        return alerts_sent
    
    def check_unusual_activity(self):
        """
        Check for unusual user activity
        
        Returns:
            Number of alerts sent
        """
        print("\n📊 Checking unusual user activity...")
        unusual_df = self.behavioral_monitor.detect_unusual_activity()
        
        alerts_sent = 0
        
        # Send alerts for critical/high severity events
        for _, row in unusual_df.iterrows():
            if row.get('severity') in ['Critical', 'High']:
                user = row.get('user', 'Unknown')
                reason = row.get('reason', 'Unusual activity')
                
                print(f"   ⚠️  Unusual activity: {user} - {reason}")
                
                activities = [
                    reason,
                    f"Alert Type: {row.get('alert_type', 'Unknown')}",
                    f"Count: {row.get('count', 'N/A')}"
                ]
                
                success = self.email_alerter.send_high_risk_user_alert(user, 0.75, activities)
                
                if success:
                    alerts_sent += 1
                    self.alerts_sent_today += 1
        
        return alerts_sent
    
    # =====================================================================
    # MONITORING CYCLE
    # =====================================================================
    
    def run_monitoring_cycle(self):
        """
        Run a single monitoring cycle (enhanced with behavioral monitoring)
        """
        print(f"\n🔍 Running monitoring cycle at {datetime.now().strftime('%H:%M:%S')}...")
        
        try:
            # Original checks
            print("\n   📋 Original Monitoring:")
            print("   Checking after-hours logins...")
            after_hours_alerts = self.check_after_hours_logins()
            print(f"   ✓ After-hours alerts: {after_hours_alerts}")
            
            print("   Checking high-risk users...")
            high_risk_alerts = self.check_high_risk_users()
            print(f"   ✓ High-risk user alerts: {high_risk_alerts}")
            
            # NEW: Behavioral monitoring checks
            print("\n   🧠 Behavioral Monitoring:")
            print("   Checking sensitive file access...")
            sensitive_alerts = self.check_sensitive_file_access()
            print(f"   ✓ Sensitive file alerts: {sensitive_alerts}")
            
            print("   Checking abnormal logins...")
            abnormal_alerts = self.check_abnormal_logins()
            print(f"   ✓ Abnormal login alerts: {abnormal_alerts}")
            
            print("   Checking unusual activity...")
            unusual_alerts = self.check_unusual_activity()
            print(f"   ✓ Unusual activity alerts: {unusual_alerts}")
            
            # Update last check time
            self.last_check_time = datetime.now()
            
            total_alerts = (after_hours_alerts + high_risk_alerts + 
                          sensitive_alerts + abnormal_alerts + unusual_alerts)
            
            print(f"\n   ✓ Monitoring cycle complete. Total alerts today: {self.alerts_sent_today}")
            print(f"   ✓ Alerts this cycle: {total_alerts}")
            
        except Exception as e:
            print(f"   ✗ Error in monitoring cycle: {e}")
            import traceback
            traceback.print_exc()
    
    def start_background_monitoring(self, interval_minutes=60, run_immediately=False):
        """
        Start background monitoring thread
        
        Args:
            interval_minutes: Minutes between monitoring cycles
            run_immediately: If True, run first cycle immediately. If False, wait interval first.
        """
        if self.monitoring_active:
            print("⚠️  Monitoring already active")
            return
        
        self.monitoring_active = True
        
        # Set initial check time to show when monitoring started
        if not run_immediately:
            self.last_check_time = datetime.now()
        
        def monitor_loop():
            # If NOT running immediately, sleep first
            if not run_immediately:
                print(f"   Background monitoring will run first check in {interval_minutes} minutes")
                time.sleep(interval_minutes * 60)
            
            # Then start the monitoring loop
            while self.monitoring_active:
                self.run_monitoring_cycle()
                time.sleep(interval_minutes * 60)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        print(f"✓ Background monitoring started (interval: {interval_minutes} minutes)")
        if run_immediately:
            print(f"   First check will run immediately")
        else:
            print(f"   First check scheduled in {interval_minutes} minutes")
    
    def stop_background_monitoring(self):
        """Stop background monitoring thread"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("✓ Background monitoring stopped")
    
    def get_monitoring_status(self):
        """Get current monitoring status"""
        return {
            'monitoring_active': self.monitoring_active,
            'last_check_time': self.last_check_time.strftime('%Y-%m-%d %H:%M:%S') if self.last_check_time else 'Never',
            'alerts_sent_today': self.alerts_sent_today,
            'nlp_model_loaded': self.nlp_analyzer.classifier is not None,
            'email_configured': self.email_alerter.sender_password != '',
            'behavioral_monitoring_enabled': True  # NEW!
        }


# Flask Blueprint for API endpoints
threat_monitoring_bp = Blueprint('threat_monitoring', __name__)

# Global threat monitor instance
threat_monitor = None


def init_threat_monitor(app, data_path='../data', model_path='../models'):
    """
    Initialize threat monitoring system with Flask app
    
    Args:
        app: Flask application
        data_path: Path to data directory
        model_path: Path to models directory
        
    Returns:
        ThreatMonitor instance
    """
    global threat_monitor
    
    if threat_monitor is None:
        threat_monitor = ThreatMonitor(data_path=data_path, model_path=model_path)
    
    # Register blueprint
    app.register_blueprint(threat_monitoring_bp, url_prefix='/api/threat-monitoring')
    
    print("✓ Threat monitoring integrated with Flask app")
    print("   ✓ 6 original API endpoints")
    print("   ✓ 5 new behavioral monitoring endpoints")
    
    return threat_monitor


# =====================================================================
# ORIGINAL API ENDPOINTS
# =====================================================================

@threat_monitoring_bp.route('/analyze-log', methods=['POST'])
def api_analyze_log():
    """API endpoint to analyze a log entry"""
    try:
        data = request.json
        log_text = data.get('log_text', '')
        send_alert = data.get('send_alert', False)
        
        if not log_text:
            return jsonify({'error': 'log_text is required'}), 400
        
        result = threat_monitor.analyze_log_entry(log_text, send_alert=send_alert)
        
        return jsonify({
            'success': True,
            'analysis': result
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/check-after-hours', methods=['POST'])
def api_check_after_hours():
    """API endpoint to check for after-hours logins"""
    try:
        alerts_sent = threat_monitor.check_after_hours_logins()
        
        return jsonify({
            'success': True,
            'alerts_sent': alerts_sent
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/check-high-risk-users', methods=['POST'])
def api_check_high_risk_users():
    """API endpoint to check for high-risk users"""
    try:
        alerts_sent = threat_monitor.check_high_risk_users()
        
        return jsonify({
            'success': True,
            'alerts_sent': alerts_sent
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/status', methods=['GET'])
def api_monitoring_status():
    """API endpoint to get monitoring status"""
    try:
        status = threat_monitor.get_monitoring_status()
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/start-monitoring', methods=['POST'])
def api_start_monitoring():
    """API endpoint to start background monitoring"""
    try:
        data = request.json or {}
        interval = data.get('interval_minutes', 60)
        
        threat_monitor.start_background_monitoring(interval_minutes=interval)
        
        return jsonify({
            'success': True,
            'message': f'Monitoring started with {interval} minute interval'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/stop-monitoring', methods=['POST'])
def api_stop_monitoring():
    """API endpoint to stop background monitoring"""
    try:
        threat_monitor.stop_background_monitoring()
        
        return jsonify({
            'success': True,
            'message': 'Monitoring stopped'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =====================================================================
# NEW: BEHAVIORAL MONITORING API ENDPOINTS
# =====================================================================

@threat_monitoring_bp.route('/behavioral-analysis', methods=['GET'])
def api_behavioral_analysis():
    """
    API endpoint to run comprehensive behavioral analysis
    
    Returns all 5 behavioral monitoring features
    """
    try:
        results = threat_monitor.run_behavioral_analysis()
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/check-sensitive-files', methods=['POST'])
def api_check_sensitive_files():
    """API endpoint to check sensitive file access"""
    try:
        alerts_sent = threat_monitor.check_sensitive_file_access()
        
        return jsonify({
            'success': True,
            'alerts_sent': alerts_sent
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/check-abnormal-logins', methods=['POST'])
def api_check_abnormal_logins():
    """API endpoint to check abnormal login behavior"""
    try:
        alerts_sent = threat_monitor.check_abnormal_logins()
        
        return jsonify({
            'success': True,
            'alerts_sent': alerts_sent
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/check-unusual-activity', methods=['POST'])
def api_check_unusual_activity():
    """API endpoint to check unusual user activity"""
    try:
        alerts_sent = threat_monitor.check_unusual_activity()
        
        return jsonify({
            'success': True,
            'alerts_sent': alerts_sent
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_monitoring_bp.route('/behavioral-status', methods=['GET'])
def api_behavioral_status():
    """
    API endpoint to get behavioral monitoring statistics
    """
    try:
        # Run quick analysis (without sending alerts)
        results = threat_monitor.behavioral_monitor.run_comprehensive_analysis()
        
        stats = {
            'after_hours_logins': results['features']['after_hours_logins']['count'],
            'sensitive_file_access': results['features']['sensitive_file_access']['count'],
            'abnormal_logins': results['features']['abnormal_logins']['count'],
            'unusual_activity': results['features']['unusual_activity']['count'],
            'behavioral_anomalies': results['features']['behavioral_anomalies']['count'],
            'total_alerts': results['summary']['total_alerts'],
            'critical_alerts': results['summary']['critical_alerts'],
            'high_alerts': results['summary']['high_alerts'],
            'users_flagged': results['summary']['users_flagged'],
            'timestamp': results['timestamp']
        }
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def main():
    """
    Test function for threat monitoring integration
    """
    print("\n" + "="*70)
    print("🧪 TESTING ENHANCED THREAT MONITORING INTEGRATION")
    print("="*70 + "\n")
    
    # Initialize monitor
    monitor = ThreatMonitor()
    
    # Test 1: Analyze sample logs
    print("\n🧪 Test 1: NLP Log Analysis")
    print("-" * 70)
    
    test_logs = [
        "User user3 logged in successfully from 192.168.1.25",
        "Failed login attempt for user admin from 192.168.1.99",
        "Unauthorized access attempt to /confidential/salaries.xlsx by user7"
    ]
    
    for log in test_logs:
        print(f"\n   Analyzing: {log}")
        result = monitor.analyze_log_entry(log, send_alert=False)
        print(f"   → Risk Level: {result['risk_level']} (Score: {result['risk_score']:.3f})")
    
    # Test 2: Behavioral analysis
    print("\n🧪 Test 2: Behavioral Analysis")
    print("-" * 70)
    results = monitor.run_behavioral_analysis()
    print(f"\n   Total Alerts: {results['summary']['total_alerts']}")
    print(f"   Critical: {results['summary']['critical_alerts']}")
    print(f"   Users Flagged: {results['summary']['users_flagged']}")
    
    # Test 3: Check monitoring status
    print("\n🧪 Test 3: Monitoring Status")
    print("-" * 70)
    status = monitor.get_monitoring_status()
    for key, value in status.items():
        print(f"   {key}: {value}")
    
    print("\n" + "="*70)
    print("✅ ENHANCED THREAT MONITORING TEST COMPLETE")
    print("="*70 + "\n")


if __name__ == '__main__':
    main()