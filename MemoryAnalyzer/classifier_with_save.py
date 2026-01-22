import pandas as pd
from sklearn.utils import shuffle
from sklearn.preprocessing import StandardScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import numpy as np

print("[*] Loading datasets...")
data_path = "Datasets/Obfuscated-MalMem2022.csv"
data_df = pd.read_csv(data_path).drop(labels=['Category'], axis=1)

label_dict = {'Malware': 1, 'Benign': 0}
data_df['Class'] = data_df['Class'].replace(label_dict).astype(int)

data_df = shuffle(data_df)

print("[*] Done\n\n[*] Processing datasets")
x = data_df.drop(labels=['Class'], axis=1)
y = data_df['Class'].values

scaler = StandardScaler()
x = scaler.fit_transform(x)

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=0)

print("[*] Done!\n\n[*] Training...")
estimators = [
    ('naive-bayes', GaussianNB()),
    ('random-forest', RandomForestClassifier(n_estimators=100, random_state=0)),
    ('decision-tree', DecisionTreeClassifier(criterion="entropy", max_depth=3))
]

clf = StackingClassifier(estimators=estimators, final_estimator=LogisticRegression(random_state=0))  
clf.fit(x_train, y_train)

print("[*] Done!\n\n[*] Evaluation")
y_pred = clf.predict(x_test)
print(classification_report(y_test, y_pred, target_names=['Benign', 'Malware']))

# Save model and scaler
print("\n[*] Saving model and scaler...")
with open('model.pkl', 'wb') as f:
    pickle.dump(clf, f)
with open('scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print("[*] Model saved as model.pkl and scaler saved as scaler.pkl")
