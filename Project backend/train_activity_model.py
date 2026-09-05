"""Train a supervised file-activity classifier from a labelled CSV.

Required columns:
write_count,delete_count,create_count,rename_count,write_entropy,
ext_diversity,sensitive_path_access,read_write_ratio,label

Labels should be Benign/Malware (or 0/1). Do not train from guessed or
heuristically generated labels; use genuinely labelled activity windows.
"""
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score
from sklearn.preprocessing import LabelEncoder

FEATURES=['write_count','delete_count','create_count','rename_count','write_entropy','ext_diversity','sensitive_path_access','read_write_ratio']

if len(sys.argv) < 2:
    raise SystemExit('Usage: python train_activity_model.py activity_training.csv')

csv_path=sys.argv[1]
df=pd.read_csv(csv_path)
missing=[c for c in FEATURES+['label'] if c not in df.columns]
if missing: raise SystemExit('Missing columns: '+', '.join(missing))

df=df.dropna(subset=FEATURES+['label']).copy()
X=df[FEATURES].astype(float)
le=LabelEncoder(); y=le.fit_transform(df['label'].astype(str))
if len(set(y))<2: raise SystemExit('Training data must contain at least two classes.')
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
model=RandomForestClassifier(n_estimators=200,max_depth=12,random_state=42,n_jobs=-1,class_weight='balanced')
model.fit(Xtr,ytr)
p=model.predict(Xte); proba=model.predict_proba(Xte)
print('Accuracy:',round(accuracy_score(yte,p),4))
print(classification_report(yte,p,target_names=le.classes_,zero_division=0))
if len(le.classes_)==2: print('ROC-AUC:',round(roc_auc_score(yte,proba[:,1]),4))
joblib.dump({'model':model,'label_encoder':le,'features':FEATURES},'activity_supervised_model.pkl')
print('Saved activity_supervised_model.pkl')
