"""
🔥 CUMULATIVE PERSISTENT ANOMALY TRACKER
==========================================

Features:
✅ Tracks file accesses CUMULATIVELY (never resets)
✅ Updates user's anomaly score in REAL-TIME as they act
✅ Triggers CRITICAL alert after 10-15 files
✅ Persists across sessions (like anomaly score)
✅ Perfect for demonstrations!

LOW THRESHOLDS FOR EASY DEMO:
- 10 files → Warning
- 15 files → CRITICAL ALERT in live feed!
"""

import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import threading


class CumulativeAnomalyTracker:
    """
    Tracks user activity cumulatively and updates anomaly scores in real-time
    """
    
    def __init__(self, data_path='../data'):
        self.data_path = data_path
        self.lock = threading.Lock()
        
        # Load historical baselines
        self.historical_baselines = self._load_historical_baselines()
        
        # Track cumulative activity (persists across sessions)
        self.cumulative_activity = {}  # username -> cumulative stats
        
        # Load or initialize cumulative data
        self._load_cumulative_data()
        
        # VERY LOW THRESHOLDS for easy demonstration
        self.thresholds = {
            'files_warning': 10,      # Warning at 10 files
            'files_critical': 15,     # CRITICAL at 15 files
            'files_extreme': 20,      # EXTREME at 20 files
            'deviation_warning': 1.2,  # 20% above baseline
            'deviation_critical': 1.5, # 50% above baseline
        }
        
        print("✅ Cumulative Anomaly Tracker initialized")
        print(f"   LOW THRESHOLDS: Warning={self.thresholds['files_warning']}, "
              f"Critical={self.thresholds['files_critical']}")
        print(f"   Tracks cumulatively - NEVER resets!")
    
    def _load_historical_baselines(self):
        """Load historical baselines from CSV data"""
        print("\n📊 Loading historical baselines...")
        
        baselines = {}
        
        # Load file access data
        files_path = os.path.join(self.data_path, 'file_access.csv')
        if os.path.exists(files_path):
            files_df = pd.read_csv(files_path)
            
            for user in files_df['user'].unique():
                user_files = files_df[files_df['user'] == user]
                baselines[user] = {
                    'historical_files': len(user_files),
                    'baseline_files': len(user_files)
                }
        
        # Default baseline for unknown users
        baselines['_default'] = {
            'historical_files': 8,
            'baseline_files': 8
        }
        
        print(f"   ✓ Loaded baselines for {len(baselines)-1} users")
        return baselines
    
    def _load_cumulative_data(self):
        """Load cumulative activity data (persists across restarts)"""
        cumulative_path = os.path.join(self.data_path, '..', 'models', 'cumulative_activity.pkl')
        
        try:
            if os.path.exists(cumulative_path):
                self.cumulative_activity = joblib.load(cumulative_path)
                print(f"   ✓ Loaded cumulative data for {len(self.cumulative_activity)} users")
            else:
                # Initialize with historical data
                for user, baseline in self.historical_baselines.items():
                    if user != '_default':
                        self.cumulative_activity[user] = {
                            'total_files': baseline['historical_files'],
                            'sensitive_files': 0,
                            'last_updated': datetime.now(),
                            'alerts_triggered': []
                        }
                print(f"   ✓ Initialized cumulative tracking for {len(self.cumulative_activity)} users")
        except Exception as e:
            print(f"   ⚠️  Could not load cumulative data: {e}")
            self.cumulative_activity = {}
    
    def _save_cumulative_data(self):
        """Save cumulative activity data to disk"""
        cumulative_path = os.path.join(self.data_path, '..', 'models', 'cumulative_activity.pkl')
        
        try:
            os.makedirs(os.path.dirname(cumulative_path), exist_ok=True)
            joblib.dump(self.cumulative_activity, cumulative_path)
        except Exception as e:
            print(f"   ⚠️  Could not save cumulative data: {e}")
    
    def on_file_access(self, username, filepath, is_sensitive=False):
        """
        Called when user accesses a file
        Updates cumulative count and checks for anomalies
        
        Returns: Anomaly detection result with CRITICAL alerts
        """
        with self.lock:
            # Initialize user if not exists
            if username not in self.cumulative_activity:
                baseline = self.historical_baselines.get(username, self.historical_baselines['_default'])
                self.cumulative_activity[username] = {
                    'total_files': baseline['historical_files'],
                    'sensitive_files': 0,
                    'last_updated': datetime.now(),
                    'alerts_triggered': []
                }
            
            # Update cumulative counts
            activity = self.cumulative_activity[username]
            activity['total_files'] += 1
            if is_sensitive:
                activity['sensitive_files'] += 1
            activity['last_updated'] = datetime.now()
            
            # Get baseline
            baseline = self.historical_baselines.get(username, self.historical_baselines['_default'])
            baseline_files = baseline['baseline_files']
            
            # Calculate deviation
            total_files = activity['total_files']
            deviation_ratio = total_files / baseline_files
            
            # Determine anomaly level
            result = self._check_anomaly_level(username, total_files, baseline_files, 
                                              activity['sensitive_files'], deviation_ratio)
            
            # Save cumulative data
            self._save_cumulative_data()
            
            # Log ONLY CRITICAL anomalies (not warning/high)
            if result['severity'] == 'CRITICAL':
                severity = result['severity']
                print(f"\n🚨 CUMULATIVE ANOMALY: {username}")
                print(f"   Severity: {severity}")
                print(f"   Total files: {total_files} (baseline: {baseline_files})")
                print(f"   Files above baseline: {total_files - baseline_files}")
                print(f"   Deviation: {(deviation_ratio-1)*100:.0f}% above baseline")
                print(f"   Anomaly Score: {result['anomaly_score']:.2f}")
                print(f"   Sensitive files: {activity['sensitive_files']}")
                
                # Record alert
                activity['alerts_triggered'].append({
                    'time': datetime.now(),
                    'severity': severity,
                    'total_files': total_files
                })
            
            return result
    
    def _check_anomaly_level(self, username, total_files, baseline_files, 
                            sensitive_files, deviation_ratio):
        """
        Check anomaly level based on cumulative activity
        """
        anomalies = []
        severity = 'LOW'
        is_anomaly = False
        anomaly_score = 0.0
        
        # Calculate how many files ABOVE baseline
        files_above_baseline = total_files - baseline_files
        
        # Check 1: Files above baseline (PRIMARY TRIGGER - RELATIVE!)
        if files_above_baseline >= self.thresholds['files_extreme']:
            anomalies.append(f"EXTREME: {files_above_baseline} files above baseline (total: {total_files}, baseline: {baseline_files})")
            severity = 'CRITICAL'
            is_anomaly = True
            anomaly_score = 0.90 + (files_above_baseline - self.thresholds['files_extreme']) * 0.01
            anomaly_score = min(anomaly_score, 0.99)  # Cap at 0.99
        elif files_above_baseline >= self.thresholds['files_critical']:
            anomalies.append(f"CRITICAL: {files_above_baseline} files above baseline (total: {total_files}, baseline: {baseline_files})")
            severity = 'CRITICAL'
            is_anomaly = True
            anomaly_score = 0.80 + (files_above_baseline - self.thresholds['files_critical']) * 0.02
        elif files_above_baseline >= self.thresholds['files_warning']:
            anomalies.append(f"WARNING: {files_above_baseline} files above baseline (total: {total_files}, baseline: {baseline_files})")
            severity = 'HIGH'
            is_anomaly = True
            anomaly_score = 0.65 + (files_above_baseline - self.thresholds['files_warning']) * 0.03
        
        # Check 2: Deviation from baseline
        if deviation_ratio >= self.thresholds['deviation_critical']:
            anomalies.append(f"High deviation: {(deviation_ratio-1)*100:.0f}% above baseline")
            if severity == 'LOW':
                severity = 'HIGH'
            is_anomaly = True
            anomaly_score = max(anomaly_score, 0.78)
        elif deviation_ratio >= self.thresholds['deviation_warning']:
            anomalies.append(f"Elevated activity: {(deviation_ratio-1)*100:.0f}% above baseline")
            if severity == 'LOW':
                severity = 'MEDIUM'
            is_anomaly = True
            anomaly_score = max(anomaly_score, 0.65)
        
        # Check 3: Sensitive files
        if sensitive_files >= 3:
            anomalies.append(f"ALERT: {sensitive_files} sensitive files accessed")
            severity = 'CRITICAL'
            is_anomaly = True
            anomaly_score = max(anomaly_score, 0.88)
        elif sensitive_files >= 2:
            anomalies.append(f"Warning: {sensitive_files} sensitive files accessed")
            if severity in ['LOW', 'MEDIUM']:
                severity = 'HIGH'
            is_anomaly = True
            anomaly_score = max(anomaly_score, 0.75)
        
        result = {
            'is_anomaly': is_anomaly,
            'severity': severity,
            'anomaly_score': anomaly_score,
            'anomalies': anomalies,
            'cumulative_stats': {
                'total_files': total_files,
                'baseline_files': baseline_files,
                'sensitive_files': sensitive_files,
                'deviation_percent': round((deviation_ratio - 1) * 100, 1),
                'deviation_ratio': round(deviation_ratio, 2)
            },
            'thresholds': {
                'at_warning': total_files >= self.thresholds['files_warning'],
                'at_critical': total_files >= self.thresholds['files_critical'],
                'at_extreme': total_files >= self.thresholds['files_extreme']
            }
        }
        
        return result
    
    def get_user_status(self, username):
        """Get cumulative status for a user"""
        with self.lock:
            if username not in self.cumulative_activity:
                return None
            
            activity = self.cumulative_activity[username]
            baseline = self.historical_baselines.get(username, self.historical_baselines['_default'])
            
            total_files = activity['total_files']
            baseline_files = baseline['baseline_files']
            deviation_ratio = total_files / baseline_files
            
            # Check current anomaly status
            anomaly_check = self._check_anomaly_level(
                username, total_files, baseline_files,
                activity['sensitive_files'], deviation_ratio
            )
            
            return {
                'username': username,
                'cumulative_stats': activity,
                'baseline': baseline,
                'current_anomaly': anomaly_check,
                'alerts_triggered_count': len(activity['alerts_triggered'])
            }
    
    def reset_user(self, username):
        """Reset user's cumulative data (for testing/demo)"""
        with self.lock:
            if username in self.cumulative_activity:
                baseline = self.historical_baselines.get(username, self.historical_baselines['_default'])
                self.cumulative_activity[username] = {
                    'total_files': baseline['historical_files'],
                    'sensitive_files': 0,
                    'last_updated': datetime.now(),
                    'alerts_triggered': []
                }
                self._save_cumulative_data()
                print(f"✅ Reset cumulative data for {username}")
                return True
            return False


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

print("\n" + "🔥"*35)
print("INITIALIZING CUMULATIVE ANOMALY TRACKER")
print("🔥"*35)

cumulative_tracker = CumulativeAnomalyTracker()

print("\n✅ CUMULATIVE TRACKER READY!")
print("   ✓ Tracks files CUMULATIVELY (never resets)")
print("   ✓ CRITICAL alert at 15 files total")
print("   ✓ Updates anomaly score in real-time")
print("   ✓ Persists across logins\n")