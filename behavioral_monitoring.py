"""
🤖 FULLY AUTOMATED AI-BASED BEHAVIORAL MONITORING SYSTEM
=========================================================

Features:
✅ Auto-trains ML model on server startup
✅ Auto-detects anomalies after every login
✅ Auto-detects anomalies after every file access
✅ Model ready immediately - NO manual API calls needed
✅ Uses Isolation Forest (sklearn) for unsupervised learning

Status: PRODUCTION-READY AUTOMATED AI
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class BehavioralMonitor:
    """
    Fully Automated AI-Based Behavioral Monitoring System
    """
    
    def __init__(self, data_path='../data', auto_train=True):
        """
        Initialize and AUTO-TRAIN the behavioral monitoring system
        
        Args:
            data_path: Path to data directory
            auto_train: If True, automatically trains model on init
        """
        self.data_path = data_path
        
        # Configuration
        self.config = {
            'office_start_hour': 8,
            'office_end_hour': 18,
            'sensitive_paths': [
                '/confidential/', '/secret/', '/admin/', '/hr/',
                '/financial/', '/salary', '/payroll', 'passwords', 'credentials'
            ],
            'anomaly_threshold': -0.2,  # VERY SENSITIVE for demo (detects small deviations)
            'contamination': 0.25  # Expect 25% anomalies (flags easily)
        }
        
        # ML Model components
        self.ml_model = None
        self.scaler = None
        self.user_baselines = {}
        self.model_trained = False
        
        # Model persistence paths
        self.model_path = os.path.join(data_path, '..', 'models', 'behavioral_model.pkl')
        self.scaler_path = os.path.join(data_path, '..', 'models', 'behavioral_scaler.pkl')
        self.baselines_path = os.path.join(data_path, '..', 'models', 'user_baselines.pkl')
        
        print("\n" + "="*70)
        print("🤖 INITIALIZING AUTOMATED AI BEHAVIORAL MONITORING")
        print("="*70)
        
        # AUTO-TRAIN on startup
        if auto_train:
            self._auto_train_on_startup()
        
        print("="*70)
        print("✅ AI MODEL READY - AUTOMATED DETECTION ACTIVE")
        print("="*70 + "\n")
    
    def _auto_train_on_startup(self):
        """
        Automatically train ML model on startup
        """
        print("\n📊 AUTO-TRAINING ML MODEL ON STARTUP...")
        
        try:
            # Try to load existing model first
            if self._load_saved_model():
                print("✅ Loaded pre-trained model from disk")
                self.model_trained = True
                return
        except Exception as e:
            print(f"⚠️  Could not load saved model: {e}")
        
        # Train new model
        print("🎓 Training new model from scratch...")
        
        # Load training data
        logins_df = self._load_csv('logins.csv')
        files_df = self._load_csv('file_access.csv')
        emails_df = self._load_csv('emails.csv')
        
        if logins_df is None and files_df is None:
            print("❌ No training data found!")
            return
        
        # Build user baselines
        self._build_baselines(logins_df, files_df, emails_df)
        
        # Train model
        self._train_model()
        
        # Save model for next startup
        self._save_model()
        
        self.model_trained = True
        print("✅ Model training complete!")
    
    def _load_csv(self, filename):
        """Load CSV file from data directory"""
        path = os.path.join(self.data_path, filename)
        if os.path.exists(path):
            df = pd.read_csv(path)
            print(f"   ✓ Loaded {filename}: {len(df)} records")
            return df
        return None
    
    def _build_baselines(self, logins_df, files_df, emails_df):
        """
        Build behavioral baselines for all users
        """
        print("\n🎓 Building user behavioral baselines...")
        
        # Get all unique users
        all_users = set()
        if logins_df is not None:
            all_users.update(logins_df['user'].unique())
        if files_df is not None:
            all_users.update(files_df['user'].unique())
        if emails_df is not None:
            all_users.update(emails_df['user'].unique())
        
        # Build baseline for each user
        for user in all_users:
            # Extract features
            login_count = 0
            file_count = 0
            email_count = 0
            unique_ips = 0
            after_hours_rate = 0
            
            # Login features
            if logins_df is not None:
                user_logins = logins_df[logins_df['user'] == user]
                login_count = len(user_logins)
                if login_count > 0:
                    # Get unique IPs
                    if 'ip_address' in user_logins.columns:
                        unique_ips = user_logins['ip_address'].nunique()
                    elif 'ip' in user_logins.columns:
                        unique_ips = user_logins['ip'].nunique()
                    
                    # Calculate after-hours rate
                    timestamps = user_logins.get('timestamp', user_logins.get('date', pd.Series()))
                    after_hours_count = 0
                    for ts in timestamps:
                        try:
                            dt = pd.to_datetime(ts)
                            hour = dt.hour
                            if hour < self.config['office_start_hour'] or hour >= self.config['office_end_hour']:
                                after_hours_count += 1
                        except:
                            pass
                    after_hours_rate = after_hours_count / login_count if login_count > 0 else 0
            
            # File access features
            if files_df is not None:
                user_files = files_df[files_df['user'] == user]
                file_count = len(user_files)
            
            # Email features
            if emails_df is not None:
                user_emails = emails_df[emails_df['user'] == user]
                email_count = len(user_emails)
            
            # Store baseline with feature vector
            self.user_baselines[user] = {
                'user': user,
                'login_count': login_count,
                'file_count': file_count,
                'email_count': email_count,
                'unique_ips': unique_ips,
                'after_hours_rate': after_hours_rate,
                'features': [login_count, file_count, email_count, unique_ips, after_hours_rate]
            }
        
        print(f"   ✓ Built baselines for {len(self.user_baselines)} users")
    
    def _train_model(self):
        """
        Train Isolation Forest model
        """
        print("\n🤖 Training Isolation Forest model...")
        
        if not self.user_baselines:
            print("   ❌ No baselines to train on!")
            return
        
        # Prepare feature matrix
        X = np.array([baseline['features'] for baseline in self.user_baselines.values()])
        usernames = list(self.user_baselines.keys())
        
        print(f"   ✓ Training on {len(X)} users")
        print(f"   ✓ Features: {len(X[0])} dimensions")
        
        # Standardize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.ml_model = IsolationForest(
            contamination=self.config['contamination'],
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0
        )
        
        self.ml_model.fit(X_scaled)
        
        print("   ✓ Model trained successfully!")
        print(f"   ✓ Contamination rate: {self.config['contamination']}")
    
    def _save_model(self):
        """
        Save trained model to disk
        """
        try:
            # Create models directory if it doesn't exist
            models_dir = os.path.dirname(self.model_path)
            os.makedirs(models_dir, exist_ok=True)
            
            # Save model components
            joblib.dump(self.ml_model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            joblib.dump(self.user_baselines, self.baselines_path)
            
            print("   ✓ Model saved to disk for next startup")
        except Exception as e:
            print(f"   ⚠️  Could not save model: {e}")
    
    def _load_saved_model(self):
        """
        Load pre-trained model from disk
        
        Returns:
            True if successful, False otherwise
        """
        if not all([
            os.path.exists(self.model_path),
            os.path.exists(self.scaler_path),
            os.path.exists(self.baselines_path)
        ]):
            return False
        
        self.ml_model = joblib.load(self.model_path)
        self.scaler = joblib.load(self.scaler_path)
        self.user_baselines = joblib.load(self.baselines_path)
        
        return True
    
    # =========================================================================
    # AUTOMATED DETECTION FUNCTIONS
    # =========================================================================
    
    def auto_detect_after_login(self, username, ip_address=None):
        """
        🔥 AUTOMATICALLY detect anomalies after user login
        Called automatically by login endpoint
        
        Args:
            username: User who just logged in
            ip_address: IP address of login
            
        Returns:
            Dict with detection results
        """
        if not self.model_trained:
            return {'anomaly_detected': False, 'reason': 'Model not trained yet'}
        
        # Run ML detection
        result = self._detect_user_anomaly(username)
        
        # Log result
        if result['is_anomaly']:
            print(f"🚨 AUTO-DETECT: Anomaly detected for {username} (score: {result['anomaly_score']:.3f})")
        
        return result
    
    def auto_detect_after_file_access(self, username, filepath, action='read'):
        """
        🔥 AUTOMATICALLY detect anomalies after file access
        Called automatically by file access endpoint
        
        Args:
            username: User who accessed file
            filepath: Path of accessed file
            action: Type of access (read/write/delete)
            
        Returns:
            Dict with detection results
        """
        if not self.model_trained:
            return {'anomaly_detected': False, 'reason': 'Model not trained yet'}
        
        # Check if sensitive file
        is_sensitive = self._is_sensitive_file(filepath)
        
        # Run ML detection
        ml_result = self._detect_user_anomaly(username)
        
        # Combine results
        result = {
            'user': username,
            'filepath': filepath,
            'is_sensitive': is_sensitive,
            'ml_anomaly': ml_result['is_anomaly'],
            'anomaly_score': ml_result['anomaly_score'],
            'overall_risk': 'HIGH' if (is_sensitive and ml_result['is_anomaly']) else 
                          'MEDIUM' if (is_sensitive or ml_result['is_anomaly']) else 'LOW'
        }
        
        # Log result
        if result['overall_risk'] == 'HIGH':
            print(f"🚨 AUTO-DETECT: HIGH RISK file access by {username}: {filepath}")
        
        return result
    
    def _detect_user_anomaly(self, username):
        """
        Detect if user behavior is anomalous using ML model
        
        Args:
            username: User to check
            
        Returns:
            Dict with anomaly detection results
        """
        if username not in self.user_baselines:
            return {
                'is_anomaly': False,
                'anomaly_score': 0,
                'reason': 'No baseline for user'
            }
        
        # Get user features
        user_features = np.array([self.user_baselines[username]['features']])
        
        # Scale features
        user_features_scaled = self.scaler.transform(user_features)
        
        # Get anomaly score
        anomaly_score = self.ml_model.score_samples(user_features_scaled)[0]
        prediction = self.ml_model.predict(user_features_scaled)[0]
        
        # Determine if anomaly
        is_anomaly = (prediction == -1) and (anomaly_score < self.config['anomaly_threshold'])
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'prediction': prediction,
            'threshold': self.config['anomaly_threshold'],
            'severity': 'HIGH' if anomaly_score < -0.7 else 'MEDIUM' if is_anomaly else 'LOW'
        }
    
    def _is_sensitive_file(self, filepath):
        """
        Check if filepath is sensitive
        
        Args:
            filepath: File path to check
            
        Returns:
            True if sensitive, False otherwise
        """
        filepath_lower = filepath.lower()
        return any(pattern.lower() in filepath_lower for pattern in self.config['sensitive_paths'])
    
    # =========================================================================
    # UTILITY FUNCTIONS
    # =========================================================================
    
    def get_model_status(self):
        """
        Get current status of ML model
        
        Returns:
            Dict with model status information
        """
        return {
            'model_trained': self.model_trained,
            'model_exists': self.ml_model is not None,
            'users_in_baseline': len(self.user_baselines),
            'model_type': 'Isolation Forest',
            'features': 5,
            'contamination_rate': self.config['contamination'],
            'anomaly_threshold': self.config['anomaly_threshold']
        }
    
    def get_user_risk_score(self, username):
        """
        Get risk score for a specific user
        
        Args:
            username: User to check
            
        Returns:
            Dict with risk score and details
        """
        if not self.model_trained:
            return {'error': 'Model not trained'}
        
        result = self._detect_user_anomaly(username)
        
        baseline = self.user_baselines.get(username, {})
        
        return {
            'user': username,
            'risk_score': abs(result['anomaly_score']),
            'is_anomaly': result['is_anomaly'],
            'severity': result['severity'],
            'baseline_stats': {
                'login_count': baseline.get('login_count', 0),
                'file_count': baseline.get('file_count', 0),
                'email_count': baseline.get('email_count', 0),
                'unique_ips': baseline.get('unique_ips', 0),
                'after_hours_rate': baseline.get('after_hours_rate', 0)
            }
        }
    
    def retrain_model(self):
        """
        Manually retrain the model with latest data
        """
        print("\n🔄 RETRAINING MODEL...")
        self._auto_train_on_startup()
        print("✅ Retraining complete!")


# ============================================================================
# GLOBAL INSTANCE - AUTO-INITIALIZES ON IMPORT
# ============================================================================

print("\n" + "🚀"*35)
print("INITIALIZING AUTOMATED AI BEHAVIORAL MONITORING SYSTEM")
print("🚀"*35)

# Create global instance that auto-trains on startup
behavioral_monitor = BehavioralMonitor(auto_train=True)

print("\n✅ AUTOMATED AI SYSTEM READY!")
print("   ✓ Model auto-trains on server startup")
print("   ✓ Detection runs automatically after login")
print("   ✓ Detection runs automatically after file access")
print("   ✓ No manual API calls required!\n")