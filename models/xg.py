import json
import pandas as pd
import numpy as np
import xgboost as xgb

from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    f1_score,
    precision_score,
    recall_score,
    precision_recall_curve,
    confusion_matrix,
    accuracy_score,
    average_precision_score
)


with open("final_output_correlated.json") as f:
    events = json.load(f)

df = pd.DataFrame(events)

df["event_time"] = pd.to_datetime(df["event_time"])
df["hour"] = df["event_time"].dt.hour

df = df.fillna("unknown")
df["suspicious"] = df["suspicious"].astype(int)


USE_ID_FEATURES = False

categorical_cols = ["role", "resource", "event_type", "source"]

if USE_ID_FEATURES:
    categorical_cols += ["ip", "mac"]

numeric_cols = ["hour"]


encoders = {}

for col in categorical_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

X = df[categorical_cols + numeric_cols].values
y = df["suspicious"].values



df["group_key"] = (
    df["user"].astype(str) + "_" +
    df["ip"].astype(str) + "_" +
    df["mac"].astype(str)
)

groups = df["group_key"]


gkf = GroupKFold(n_splits=5)

results_opt = []
results_05 = []

for fold, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups)):

    print(f"\n===== Fold {fold+1} =====")

    X_train, X_val = X[train_idx], X[val_idx]
    y_train, y_val = y[train_idx], y[val_idx]


    model = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        tree_method="hist"
    )

    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

    probs = model.predict_proba(X_val)[:, 1]

    precision_arr, recall_arr, thresholds = precision_recall_curve(y_val, probs)
    f1_arr = 2 * (precision_arr * recall_arr) / (precision_arr + recall_arr + 1e-8)
    best_idx = np.argmax(f1_arr)
    best_threshold = thresholds[best_idx]

    preds_opt = (probs >= best_threshold).astype(int)

    acc_opt = accuracy_score(y_val, preds_opt)
    f1_opt = f1_score(y_val, preds_opt)
    precision_opt = precision_score(y_val, preds_opt)
    recall_opt = recall_score(y_val, preds_opt)
    pr_auc = average_precision_score(y_val, probs)

    results_opt.append((acc_opt, f1_opt, precision_opt, recall_opt))

    print(f"\n--- Threshold ottimale ---")
    print(f"Threshold: {best_threshold:.4f}")
    print(f"Accuracy: {acc_opt:.4f}")
    print(f"F1: {f1_opt:.4f}")
    print(f"Precision: {precision_opt:.4f}")
    print(f"Recall: {recall_opt:.4f}")
    print(f"PR-AUC: {pr_auc:.4f}")

    print("Confusion Matrix (OPT):")
    print(confusion_matrix(y_val, preds_opt))

    preds_05 = (probs >= 0.5).astype(int)

    acc_05 = accuracy_score(y_val, preds_05)
    f1_05 = f1_score(y_val, preds_05)
    precision_05 = precision_score(y_val, preds_05)
    recall_05 = recall_score(y_val, preds_05)

    results_05.append((acc_05, f1_05, precision_05, recall_05))

    print(f"\n--- Threshold 0.5 ---")
    print(f"Accuracy: {acc_05:.4f}")
    print(f"F1: {f1_05:.4f}")
    print(f"Precision: {precision_05:.4f}")
    print(f"Recall: {recall_05:.4f}")

    print("Confusion Matrix (0.5):")
    print(confusion_matrix(y_val, preds_05))



def avg_results(results):
    return np.mean(results, axis=0)

avg_opt = avg_results(results_opt)
avg_05 = avg_results(results_05)

print("\n===== FINAL RESULTS =====")

print("\n Threshold Ottimale")
print(f"Accuracy: {avg_opt[0]:.4f}")
print(f"F1: {avg_opt[1]:.4f}")
print(f"Precision: {avg_opt[2]:.4f}")
print(f"Recall: {avg_opt[3]:.4f}")

print("\n Threshold 0.5")
print(f"Accuracy: {avg_05[0]:.4f}")
print(f"F1: {avg_05[1]:.4f}")
print(f"Precision: {avg_05[2]:.4f}")
print(f"Recall: {avg_05[3]:.4f}")