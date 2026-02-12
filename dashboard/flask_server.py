from flask import Flask
from flask_cors import CORS
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import dashboard routes
from dashboard_routes import register_dashboard_routes

# Import threat monitoring (NLP + Email)
try:
    from threat_monitoring_integration import init_threat_monitor, threat_monitor
    THREAT_MONITORING_AVAILABLE = True
    print("✓ Threat monitoring modules imported successfully")
except ImportError as e:
    print(f"⚠️  Threat monitoring not available: {e}")
    print("   Copy these files to project root:")
    print("   - nlp_log_analyzer.py")
    print("   - email_alerter.py")
    print("   - threat_monitoring_integration.py")
    THREAT_MONITORING_AVAILABLE = False

# ============================================================================
# FLASK APP INITIALIZATION
# ============================================================================

# Create Flask app
app = Flask(__name__, static_folder='static')
app.secret_key = 'insider-threat-detection-secret-2024'  # Change in production!
CORS(app, supports_credentials=True)

# Register all dashboard routes (existing functionality)
register_dashboard_routes(app)

# ============================================================================
# INITIALIZE THREAT MONITORING (NLP + EMAIL)
# ============================================================================

if THREAT_MONITORING_AVAILABLE:
    try:
        # Get paths
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        DATA_DIR = os.path.join(BASE_DIR, 'data')
        MODEL_DIR = os.path.join(BASE_DIR, 'models')
        
        print(f"\n📂 Data directory: {DATA_DIR}")
        print(f"📂 Model directory: {MODEL_DIR}")
        
        # Initialize threat monitoring system (returns the monitor instance)
        monitor = init_threat_monitor(app, data_path=DATA_DIR, model_path=MODEL_DIR)
        
        # Start background monitoring (checks every 60 minutes)
        monitor.start_background_monitoring(interval_minutes=60)
        
        print("✅ Threat monitoring initialized successfully!")
        print("   - NLP log analysis enabled")
        print("   - Email alerting configured")
        print("   - Background monitoring started (60 min interval)")
        print("   - 6 new API endpoints added")
        
    except Exception as e:
        print(f"❌ Could not initialize threat monitoring: {e}")
        print("   Dashboard will work without NLP/Email features")
else:
    print("\n⚠️  Running without threat monitoring features")
    print("   To enable:")
    print("   1. Copy nlp_log_analyzer.py to project root")
    print("   2. Copy email_alerter.py to project root")
    print("   3. Copy threat_monitoring_integration.py to project root")
    print("   4. Run: python nlp_log_analyzer.py (to train models)")
    print("   5. Restart flask_server.py")

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print(" 🛡️  SOC INSIDER THREAT DETECTION DASHBOARD")
    print("="*70)
    print()
    print(" 📊 Dashboard URL:  http://localhost:5000/dashboard")
    print(" 🔐 Login:          admin / admin123")
    print()
    
    if THREAT_MONITORING_AVAILABLE:
        print(" 🔍 AI-POWERED FEATURES:")
        print("    ✓ Real-Time NLP Log Analysis")
        print("    ✓ Automated Email Alerting")
        print("    ✓ After-Hours Login Detection")
        print("    ✓ High-Risk User Monitoring")
        print("    ✓ Background Threat Monitoring (60-min cycles)")
        print()
    
    print("="*70 + "\n")
    
    # RENDER DEPLOYMENT FIX: Get port from environment variable
    port = int(os.environ.get('PORT', 5000))
    
    # Disable debug mode in production (Render deployment)
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)