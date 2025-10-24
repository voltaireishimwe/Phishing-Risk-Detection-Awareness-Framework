import pickle
import os
import numpy as np

def debug_model_files():
    print("=== DEBUGGING MODEL FILES ===")
    
    files = ['phishing_model.pkl', 'feature_processor.pkl', 'label_encoder.pkl']
    
    for file in files:
        print(f"\n--- Checking {file} ---")
        if os.path.exists(file):
            print(f"✓ File exists")
            print(f"  Size: {os.path.getsize(file)} bytes")
            
            try:
                with open(file, 'rb') as f:
                    obj = pickle.load(f)
                print(f"✓ File loaded successfully")
                print(f"  Type: {type(obj)}")
                
                # Check specific attributes based on file type
                if file == 'phishing_model.pkl':
                    if hasattr(obj, 'predict'):
                        print("  ✓ Has predict method")
                    else:
                        print("  ✗ Missing predict method")
                    
                    if hasattr(obj, 'predict_proba'):
                        print("  ✓ Has predict_proba method")
                    else:
                        print("  ✗ Missing predict_proba method")
                        
                    if hasattr(obj, 'feature_importances_'):
                        print("  ✓ Has feature_importances_")
                    else:
                        print("  ✗ Missing feature_importances_")
                        
                elif file == 'label_encoder.pkl':
                    if hasattr(obj, 'classes_'):
                        print(f"  Classes: {obj.classes_}")
                    else:
                        print("  ✗ No classes attribute")
                        
            except Exception as e:
                print(f"✗ Error loading {file}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"✗ File not found")

if __name__ == '__main__':
    debug_model_files()