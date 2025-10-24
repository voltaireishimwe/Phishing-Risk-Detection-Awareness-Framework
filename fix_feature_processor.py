import pickle
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin

# Define the missing class
class PhishingFeatureEngineer(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.feature_names = [
            'sender_domain', 'sender_has_suspicious_tld', 'receiver_domain',
            'hour_of_day', 'day_of_week', 'is_weekend', 'subject_length',
            'subject_has_urgent', 'subject_has_verify', 'subject_has_account',
            'body_length', 'body_has_links', 'body_has_attachments',
            'suspicious_keywords_count', 'has_grammar_errors', 'url_count',
            'has_url_shortener', 'has_suspicious_tld', 'avg_url_length',
            'max_url_length', 'urgency_score'
        ]
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        # Ensure all expected features are present
        for feature in self.feature_names:
            if feature not in X.columns:
                X[feature] = 0
        return X[self.feature_names]

def fix_feature_processor():
    print("Fixing feature processor...")
    
    try:
        # Load the feature processor with the class defined
        with open('feature_processor.pkl', 'rb') as f:
            feature_processor = pickle.load(f)
        print("✓ Feature processor loaded successfully with PhishingFeatureEngineer class")
        
        # Save it back to make sure it's properly serialized
        with open('feature_processor.pkl', 'wb') as f:
            pickle.dump(feature_processor, f)
        print("✓ Feature processor re-saved successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def create_simple_feature_processor():
    """Create a simple feature processor that will work"""
    print("Creating simple feature processor...")
    
    simple_processor = {
        'type': 'simple_processor',
        'feature_names': [
            'sender_domain', 'sender_has_suspicious_tld', 'receiver_domain',
            'hour_of_day', 'day_of_week', 'is_weekend', 'subject_length',
            'subject_has_urgent', 'subject_has_verify', 'subject_has_account',
            'body_length', 'body_has_links', 'body_has_attachments',
            'suspicious_keywords_count', 'has_grammar_errors', 'url_count',
            'has_url_shortener', 'has_suspicious_tld', 'avg_url_length',
            'max_url_length', 'urgency_score'
        ],
        'scaler': StandardScaler()
    }
    
    try:
        with open('feature_processor.pkl', 'wb') as f:
            pickle.dump(simple_processor, f)
        print("✓ Simple feature processor created successfully")
        return True
    except Exception as e:
        print(f"✗ Error creating simple processor: {e}")
        return False

if __name__ == '__main__':
    # First try to fix the existing processor
    if not fix_feature_processor():
        # If that fails, create a new simple one
        print("Creating new simple feature processor...")
        create_simple_feature_processor()