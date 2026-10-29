import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
from src.components.data_transformation import AdversarialThreatTransformer

def run_training():
    data_path = os.path.join("data", "dataset.csv")
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at '{data_path}'. Please check Phase 3.")
        return

    print("Loading dataset...")
    try:
        df = pd.read_csv(data_path, encoding="utf-8")
    except UnicodeDecodeError:
        df = pd.read_csv(data_path, encoding="latin-1")

    # Standardize column names across common datasets
    if 'v1' in df.columns and 'v2' in df.columns:
        df = df[['v1', 'v2']].rename(columns={'v1': 'label', 'v2': 'text'})
    elif 'Category' in df.columns and 'Message' in df.columns:
        df = df[['Category', 'Message']].rename(columns={'Category': 'label', 'Message': 'text'})
    elif 'label' in df.columns and 'text' in df.columns:
        df = df[['label', 'text']]

    df = df.dropna(subset=['text', 'label'])
    
    # Map labels (ham/clean -> 0, spam -> 1)
    df['label'] = df['label'].astype(str).str.strip().str.lower().map({
        'ham': 0, 'clean': 0, '0': 0, 0: 0,
        'spam': 1, '1': 1, 1: 1
    })
    df = df.dropna(subset=['label'])
    df['label'] = df['label'].astype(int)

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        df['text'], df['label'], test_size=0.2, random_state=42, stratify=df['label']
    )

    print("Transforming text with Adversarial Normalization...")
    transformer = AdversarialThreatTransformer(max_features=5000)
    X_train_vec = transformer.fit_transform(X_train)
    X_test_vec = transformer.transform(X_test)

    print("Training Balanced Classifier...")
    model = LogisticRegression(max_iter=1000, class_weight='balanced')
    model.fit(X_train_vec, y_train)

    preds = model.predict(X_test_vec)
    print(f"\n--- Model Performance Evaluation ---")
    print(f"Test Accuracy: {accuracy_score(y_test, preds)*100:.2f}%\n")
    print(classification_report(y_test, preds, target_names=["Ham (Clean)", "Spam / Threat"]))

    # Export trained artifacts
    os.makedirs("outputs", exist_ok=True)
    joblib.dump(transformer, os.path.join("outputs", "transformer.pkl"))
    joblib.dump(model, os.path.join("outputs", "model.pkl"))
    print("Model and Transformer artifacts saved successfully in outputs/ directory.")

if __name__ == "__main__":
    run_training()