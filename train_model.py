"""
Train the NLP Intent Detection Model
Run this ONCE to train the model
"""

from chat_intent_detector import ChatIntentDetector

def main():
    print("="*70)
    print("TRAINING NLP MALICIOUS INTENT DETECTION MODEL")
    print("="*70)
    
    # Initialize detector
    detector = ChatIntentDetector(model_type='naive_bayes')
    
    # Train model (uses built-in synthetic data)
    print("\n🎓 Training model...")
    accuracy = detector.train_model()
    
    # Save model
    print("\n💾 Saving model...")
    detector.save_model('models/chat_intent_model.pkl')
    
    print("\n" + "="*70)
    print(f"✅ TRAINING COMPLETE - Accuracy: {accuracy:.2%}")
    print("   Model saved to: models/chat_intent_model.pkl")
    print("="*70)

if __name__ == '__main__':
    main()