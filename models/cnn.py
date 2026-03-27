import json
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score, precision_recall_curve, confusion_matrix


with open("final_output_correlated.json") as f:
    events = json.load(f)

df = pd.DataFrame(events)
df["event_time"] = pd.to_datetime(df["event_time"])
df["hour"] = df["event_time"].dt.hour
df = df.fillna("unknown")
df["suspicious"] = df["suspicious"].astype(int)

categorical_cols = ["ip","role","mac", "resource","event_type","source"]


encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

numeric_cols = ["status_code","hour"]

cat_tensor = torch.tensor(df[categorical_cols].values, dtype=torch.long)
num_tensor = torch.tensor(df[numeric_cols].values, dtype=torch.float)

X = torch.cat([cat_tensor.float(), num_tensor], dim=1)
y = torch.tensor(df["suspicious"].values, dtype=torch.float)

class CNN1DTabular(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 16, kernel_size=3, padding=1)
        self.conv2 = nn.Conv1d(16, 32, kernel_size=3, padding=1)
        self.dropout = nn.Dropout(0.3)
        self.fc = nn.Linear(32 * input_dim, 1)

    def forward(self, x):
        x = x.unsqueeze(1)          
        x = F.relu(self.conv1(x))
        x = F.relu(self.conv2(x))
        x = x.flatten(start_dim=1)   
        x = self.dropout(x)
        return self.fc(x).squeeze()  


def train(model, X_train, y_train, X_test=None, y_test=None, epochs=50, lr=0.0003):
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)
    criterion = nn.BCEWithLogitsLoss()
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out = model(X_train)
        loss = criterion(out, y_train)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 0.5)
        optimizer.step()

        if epoch % 10 == 0 and X_test is not None:
            model.eval()
            with torch.no_grad():
                logits = model(X_test)
                probs = torch.sigmoid(logits)
                pred_labels = (probs >= 0.5).float()
                f1 = f1_score(y_test.cpu(), pred_labels.cpu())
                acc = (pred_labels == y_test).sum() / y_test.size(0)
                print(f"Epoch {epoch}, Loss: {loss.item():.4f}, Test Acc: {acc:.4f}, F1: {f1:.4f}")


def kfold_train(model_class, X, y, k=5, epochs=50, lr=0.0003):
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        print(f"\n===== Fold {fold+1}/{k} =====")
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        model = model_class(input_dim=X.shape[1])
        train(model, X_train, y_train, X_val, y_val, epochs=epochs, lr=lr)

        model.eval()
        with torch.no_grad():
            logits = model(X_val)
            probs = torch.sigmoid(logits).cpu().numpy()
            y_val_cpu = y_val.cpu().numpy()

            # Soglia adattiva
            precision_arr, recall_arr, thresholds = precision_recall_curve(y_val_cpu, probs)
            f1_per_threshold = 2 * (precision_arr * recall_arr) / (precision_arr + recall_arr + 1e-8)
            best_idx = f1_per_threshold.argmax()
            fold_best_threshold = thresholds[best_idx]
            preds = (probs >= fold_best_threshold).astype(float)

            acc = (preds == y_val_cpu).mean()
            f1 = f1_score(y_val_cpu, preds)
            recall = recall_score(y_val_cpu, preds)
            precision = precision_score(y_val_cpu, preds)

            print(f"Fold {fold+1} → Acc: {acc:.4f}, F1: {f1:.4f}, Precision: {precision:.4f}, Recall: {recall:.4f}")

            cm = confusion_matrix(y_val_cpu, preds)
            cm_df = pd.DataFrame(cm, index=["True 0", "True 1"], columns=["Pred 0", "Pred 1"])
            print("Confusion Matrix:")
            print(cm_df)

kfold_train(model_class=CNN1DTabular, X=X, y=y, k=5, epochs=100)