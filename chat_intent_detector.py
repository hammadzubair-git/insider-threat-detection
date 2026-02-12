"""
🔍 NLP-BASED MALICIOUS INTENT DETECTION FOR CHAT SYSTEM
========================================================

Purpose:
    Analyze chat messages to detect insider threat indicators such as:
    - Data exfiltration attempts
    - Unauthorized access discussions
    - Confidential file monitoring
    - Policy violation planning

Approach:
    Traditional NLP + Machine Learning (Non-Deep Learning)
    - Text preprocessing (tokenization, normalization, stop-word removal)
    - Feature extraction (TF-IDF, keyword matching, n-grams)
    - Classification (Naive Bayes / Logistic Regression)
    - Risk scoring and alerting

Author: Final Year Project - Insider Threat Detection System
"""

import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
import os
from datetime import datetime
from collections import defaultdict

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
    nltk.data.find('corpora/stopwords')
    nltk.data.find('corpora/wordnet')
except LookupError:
    nltk.download('punkt')
    nltk.download('stopwords')
    nltk.download('wordnet')
    nltk.download('averaged_perceptron_tagger')


class ChatIntentDetector:
    """
    NLP-based malicious intent detection for chat messages
    
    Features:
    - Text preprocessing pipeline
    - Keyword-based threat detection
    - TF-IDF feature extraction
    - Machine learning classification
    - Risk scoring and severity assessment
    """
    
    def __init__(self, model_type='naive_bayes'):
        """
        Initialize the intent detector
        
        Args:
            model_type: 'naive_bayes', 'logistic_regression', or 'random_forest'
        """
        self.model_type = model_type
        self.model = None
        self.vectorizer = None
        self.lemmatizer = WordNetLemmatizer()
        self.stop_words = set(stopwords.words('english'))
        
        # Insider threat keyword dictionaries
        self.threat_keywords = {
            'data_exfiltration': {
                'keywords': ['copy', 'transfer', 'send', 'email', 'gmail', 'personal', 
                           'usb', 'drive', 'download', 'export', 'extract', 'leak',
                           'upload', 'cloud', 'dropbox', 'share', 'forward'],
                'weight': 0.4
            },
            'unauthorized_access': {
                'keywords': ['password', 'credentials', 'bypass', 'hack', 'admin',
                           'root', 'privilege', 'escalate', 'unauthorized', 'access',
                           'login', 'account', 'vpn', 'firewall', 'security'],
                'weight': 0.35
            },
            'confidential_monitoring': {
                'keywords': ['monitor', 'watch', 'track', 'observe', 'spy', 'surveillance',
                           'log', 'record', 'sniff', 'capture', 'intercept'],
                'weight': 0.25
            },
            'policy_violation': {
                'keywords': ['violate', 'break', 'ignore', 'policy', 'rule', 'regulation',
                           'compliance', 'unauthorized', 'forbidden', 'restricted'],
                'weight': 0.3
            },
            'social_engineering': {
                'keywords': ['trick', 'pretend', 'impersonate', 'fake', 'deceive',
                           'manipulate', 'convince', 'urgent', 'emergency'],
                'weight': 0.3
            }
        }
        
        # Sensitive data identifiers
        self.sensitive_terms = [
            'salary', 'confidential', 'secret', 'classified', 'proprietary',
            'financial', 'revenue', 'client', 'customer', 'database',
            'hr', 'payroll', 'social security', 'credit card', 'ssn'
        ]
        
        # User message history for behavioral analysis
        self.user_history = defaultdict(list)
        
        print("🔍 Chat Intent Detector initialized")
        print(f"   Model type: {model_type}")
        print(f"   Threat categories: {len(self.threat_keywords)}")
    
    # ========================================================================
    # STAGE 1: TEXT PREPROCESSING
    # ========================================================================
    
    def preprocess_text(self, text):
        """
        Clean and normalize text for analysis
        
        Pipeline:
        1. Lowercase conversion
        2. Remove URLs, emails, special characters
        3. Tokenization
        4. Stop-word removal
        5. Lemmatization
        
        Args:
            text: Raw message string
            
        Returns:
            Preprocessed text string
        """
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = re.sub(r'http\S+|www\S+', '', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', 'EMAIL_ADDRESS', text)
        
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-zA-Z\s]', '', text)
        
        # Tokenize
        tokens = word_tokenize(text)
        
        # Remove stop words and lemmatize
        processed_tokens = []
        for token in tokens:
            if token not in self.stop_words and len(token) > 2:
                lemma = self.lemmatizer.lemmatize(token)
                processed_tokens.append(lemma)
        
        return ' '.join(processed_tokens)
    
    # ========================================================================
    # STAGE 2: FEATURE EXTRACTION
    # ========================================================================
    
    def extract_keyword_features(self, text):
        """
        Extract keyword-based threat features
        
        Returns:
            Dictionary with keyword match scores per category
        """
        text_lower = text.lower()
        tokens = text_lower.split()
        
        features = {}
        
        for category, data in self.threat_keywords.items():
            keywords = data['keywords']
            matches = sum(1 for word in tokens if word in keywords)
            
            # Normalize by message length
            score = (matches / len(tokens)) * data['weight'] if tokens else 0
            features[f'{category}_score'] = score
        
        # Check for sensitive terms
        sensitive_count = sum(1 for term in self.sensitive_terms 
                             if term in text_lower)
        features['sensitive_terms_count'] = sensitive_count
        
        return features
    
    def create_ngrams(self, text, n=2):
        """
        Generate n-grams for context analysis
        
        Args:
            text: Preprocessed text
            n: N-gram size (2 for bigrams, 3 for trigrams)
            
        Returns:
            List of n-grams
        """
        tokens = text.split()
        ngrams = []
        
        for i in range(len(tokens) - n + 1):
            ngram = '_'.join(tokens[i:i+n])
            ngrams.append(ngram)
        
        return ngrams
    
    # ========================================================================
    # STAGE 3: MODEL TRAINING
    # ========================================================================
    
    def prepare_training_data(self):
        """
        Generate synthetic training data for demonstration
        
        In production, this would load from a labeled dataset
        
        Returns:
            X: Messages, y: Labels (0=Normal, 1=Suspicious)
        """
        # Suspicious messages (labeled as 1)
        suspicious_messages = [
            "I need to copy the client database to my personal USB drive",
            "Can you send me the salary spreadsheet to my Gmail?",
            "I'll transfer the confidential files tonight after everyone leaves",
            "Does anyone know the admin password for the financial system?",
            "I've been monitoring who accesses the HR folder",
            "Let's bypass the firewall using the VPN credentials",
            "Send me the customer data to my personal email",
            "I'm downloading the proprietary source code to my laptop",
            "Can you share the encryption keys on WhatsApp?",
            "I need to export all client records before Friday",
            "Watching the system logs to see who accesses payroll",
            "Copy the secret project files to cloud storage",
            "I'll leak the revenue numbers to competitors",
            "Bypass security controls to access restricted folders",
            "Transfer classified documents to external drive",
            "Send social security numbers to personal account",
            "I'm recording all email communications secretly",
            "Let's violate the data retention policy",
            "Download customer credit card information urgently",
            "Monitor employee activities without authorization"
        ]
        
        # Normal messages (labeled as 0)
        normal_messages = [
            "Meeting scheduled for 3pm in conference room A",
            "Can you review my report by end of day?",
            "Thanks for the presentation, very informative",
            "I'll be working from home tomorrow",
            "Great job on the project delivery!",
            "Let's discuss the budget in our next meeting",
            "Can you help me with this Excel formula?",
            "The printer on the 3rd floor is not working",
            "Coffee break at 10:30, anyone interested?",
            "Please submit timesheets by Friday",
            "The training session was very helpful",
            "Can we reschedule our 1-on-1 meeting?",
            "I've updated the shared folder with new documents",
            "Reminder: team lunch on Thursday",
            "The network seems slow today",
            "Thank you for your quick response",
            "I'll send the meeting notes later today",
            "Can you recommend a good project management tool?",
            "The new office layout looks great",
            "Happy to help with your questions anytime"
        ]
        
        # Combine and create labels
        messages = suspicious_messages + normal_messages
        labels = [1] * len(suspicious_messages) + [0] * len(normal_messages)
        
        return messages, labels
    
    def train_model(self, messages=None, labels=None):
        """
        Train the intent classification model
        
        Args:
            messages: List of training messages
            labels: List of labels (0=Normal, 1=Suspicious)
        """
        print("\n🎓 Training malicious intent detection model...")
        
        # Use synthetic data if not provided
        if messages is None or labels is None:
            messages, labels = self.prepare_training_data()
        
        # Preprocess messages
        print("   📝 Preprocessing messages...")
        processed_messages = [self.preprocess_text(msg) for msg in messages]
        
        # Create TF-IDF features
        print("   🔢 Extracting TF-IDF features...")
        self.vectorizer = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2),  # Unigrams and bigrams
            min_df=1,
            max_df=0.8
        )
        
        X = self.vectorizer.fit_transform(processed_messages)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        # Train model based on type
        print(f"   🤖 Training {self.model_type} model...")
        
        if self.model_type == 'naive_bayes':
            self.model = MultinomialNB(alpha=1.0)
        elif self.model_type == 'logistic_regression':
            self.model = LogisticRegression(max_iter=1000, random_state=42)
        else:
            from sklearn.ensemble import RandomForestClassifier
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n   ✅ Model trained successfully!")
        print(f"   📊 Accuracy: {accuracy:.2%}")
        print(f"   📈 Training samples: {len(messages)}")
        print(f"      - Suspicious: {sum(labels)}")
        print(f"      - Normal: {len(labels) - sum(labels)}")
        
        # Detailed metrics
        print("\n   📋 Classification Report:")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Normal', 'Suspicious']))
        
        return accuracy
    
    # ========================================================================
    # STAGE 4: INTENT DETECTION & RISK SCORING
    # ========================================================================
    
    def analyze_message(self, message, username=None):
        """
        Analyze a chat message for malicious intent
        
        Args:
            message: Chat message text
            username: Username (optional, for history tracking)
            
        Returns:
            Dictionary with analysis results
        """
        if not self.model or not self.vectorizer:
            return {
                'error': 'Model not trained. Call train_model() first.',
                'is_suspicious': False
            }
        
        # Preprocess
        processed_message = self.preprocess_text(message)
        
        # Extract features
        keyword_features = self.extract_keyword_features(message)
        
        # TF-IDF vectorization
        message_vector = self.vectorizer.transform([processed_message])
        
        # Predict
        prediction = self.model.predict(message_vector)[0]
        confidence = self.model.predict_proba(message_vector)[0]
        
        # Calculate comprehensive risk score
        ml_confidence = confidence[1]  # Probability of being suspicious
        keyword_score = sum(keyword_features.values())
        
        # User history score (if tracking)
        history_score = 0.0
        if username and username in self.user_history:
            recent_suspicious = sum(1 for msg in self.user_history[username][-10:] 
                                   if msg.get('is_suspicious', False))
            history_score = recent_suspicious / min(10, len(self.user_history[username]))
        
        # Combined risk score (weighted average)
        risk_score = (
            ml_confidence * 0.5 +  # ML model confidence: 50%
            keyword_score * 0.3 +  # Keyword matching: 30%
            history_score * 0.2    # User history: 20%
        )
        
        # Determine severity
        if risk_score >= 0.7:
            severity = 'HIGH'
        elif risk_score >= 0.4:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Identify threat category
        threat_category = None
        if prediction == 1:
            max_category = max(keyword_features.items(), 
                             key=lambda x: x[1] if '_score' in x[0] else 0)
            threat_category = max_category[0].replace('_score', '')
        
        # Build result
        result = {
            'original_message': message,
            'processed_message': processed_message,
            'is_suspicious': bool(prediction == 1),
            'confidence': float(ml_confidence),
            'risk_score': float(risk_score),
            'severity': severity,
            'threat_category': threat_category,
            'keyword_features': keyword_features,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': username
        }
        
        # Update user history
        if username:
            self.user_history[username].append(result)
        
        return result
    
    def should_alert(self, analysis_result):
        """
        Determine if an alert should be generated
        
        Args:
            analysis_result: Output from analyze_message()
            
        Returns:
            Boolean indicating if alert should be sent
        """
        # Alert on medium and high severity
        return analysis_result['severity'] in ['MEDIUM', 'HIGH']
    
    # ========================================================================
    # MODEL PERSISTENCE
    # ========================================================================
    
    def save_model(self, filepath='../models/chat_intent_model.pkl'):
        """Save trained model and vectorizer to disk"""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer,
            'model_type': self.model_type,
            'threat_keywords': self.threat_keywords
        }
        
        joblib.dump(model_data, filepath)
        print(f"✅ Model saved to {filepath}")
    
    def load_model(self, filepath='../models/chat_intent_model.pkl'):
        """Load trained model from disk"""
        if not os.path.exists(filepath):
            print(f"❌ Model file not found: {filepath}")
            return False
        
        model_data = joblib.load(filepath)
        
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']
        self.model_type = model_data['model_type']
        self.threat_keywords = model_data['threat_keywords']
        
        print(f"✅ Model loaded from {filepath}")
        return True


# ============================================================================
# DEMONSTRATION & TESTING
# ============================================================================

def demo_intent_detection():
    """
    Demonstrate the intent detection system
    """
    print("\n" + "="*70)
    print("🔍 NLP-BASED MALICIOUS INTENT DETECTION - DEMONSTRATION")
    print("="*70)
    
    # Initialize detector
    detector = ChatIntentDetector(model_type='naive_bayes')
    
    # Train model
    detector.train_model()
    
    # Test messages
    test_messages = [
        ("Meeting at 3pm in room A", "alice"),
        ("I'll copy the client database to my USB drive", "bob"),
        ("Can you send salary data to my personal email?", "charlie"),
        ("Thanks for the update on the project", "alice"),
        ("I'm monitoring who accesses the HR folder", "bob"),
        ("Let's have coffee at 10:30", "david"),
        ("Bypass the firewall using VPN credentials", "eve"),
        ("The presentation was very informative", "alice")
    ]
    
    print("\n" + "="*70)
    print("📨 ANALYZING TEST MESSAGES")
    print("="*70)
    
    for message, username in test_messages:
        result = detector.analyze_message(message, username)
        
        print(f"\n{'='*70}")
        print(f"👤 User: {username}")
        print(f"💬 Message: {message}")
        print(f"{'='*70}")
        print(f"🎯 Classification: {'🚨 SUSPICIOUS' if result['is_suspicious'] else '✅ NORMAL'}")
        print(f"📊 Confidence: {result['confidence']:.2%}")
        print(f"⚠️  Risk Score: {result['risk_score']:.2f}")
        print(f"🔺 Severity: {result['severity']}")
        
        if result['threat_category']:
            print(f"🏷️  Threat Category: {result['threat_category']}")
        
        if detector.should_alert(result):
            print(f"🚨 ALERT: Security team should be notified!")
    
    # Save model
    detector.save_model()
    
    print("\n" + "="*70)
    print("✅ DEMONSTRATION COMPLETE")
    print("="*70)


if __name__ == '__main__':
    # Run demonstration
    demo_intent_detection()