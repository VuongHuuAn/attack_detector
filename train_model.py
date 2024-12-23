import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime
import glob

def load_data():
    print("[*] Loading dataset...")
    csv_file = "network_traffic_dataset.csv"
    df = pd.read_csv(csv_file)
    print(f"[+] Loaded {csv_file}")
    return df

def train_model():
    # Load data
    df = load_data()
    
    print("\n[*] Dataset Statistics:")
    print(f"Total samples: {len(df)}")
    print(f"Attack1 samples: {len(df[df['label'] == 1])}")
    print(f"Attack2 samples: {len(df[df['label'] == 2])}")
    
    # Select features for training
    feature_columns = [
        'src_port', 'dst_port', 'packet_len', 'tcp_flags', 'window_size',
        'rst_flag', 'ack_flag', 'syn_flag', 'rst_ack_flags'
    ]
    
    X = df[feature_columns]
    y = df['label']
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\n[*] Training set size: {len(X_train)}")
    print(f"[*] Testing set size: {len(X_test)}")
    
    # Scale features
    print("\n[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train Random Forest model
    print("\n[*] Training Random Forest model...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    rf_model.fit(X_train_scaled, y_train)
    
    # Evaluate model
    print("\n[*] Evaluating model...")
    y_pred = rf_model.predict(X_test_scaled)
    
    # Print classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Attack1', 'Attack2']))
    
    # Create confusion matrix plot
    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_test, y_pred)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    
    # Save confusion matrix plot
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    plt.savefig(f'confusion_matrix_{timestamp}.png')
    print(f"\n[+] Confusion matrix saved as confusion_matrix_{timestamp}.png")
    
    # Feature importance
    feature_importance = pd.DataFrame({
        'feature': feature_columns,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\nFeature Importance:")
    print(feature_importance)
    
    # Save model and scaler
    print("\n[*] Saving model and scaler...")
    joblib.dump(rf_model, 'ids_model.pkl')
    joblib.dump(scaler, 'ids_scaler.pkl')  # Lưu scaler
    print("[+] Model saved as ids_model.pkl")
    print("[+] Scaler saved as ids_scaler.pkl")
    
    # Save feature importance plot
    plt.figure(figsize=(10, 6))
    sns.barplot(x='importance', y='feature', data=feature_importance)
    plt.title('Feature Importance')
    plt.savefig(f'feature_importance_{timestamp}.png')
    print(f"[+] Feature importance plot saved as feature_importance_{timestamp}.png")
    
    return rf_model, scaler

if __name__ == "__main__":
    print("[*] Starting model training process...")
    model, scaler = train_model()