import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os
os.makedirs('models', exist_ok=True)


# ---- 1) URL Classification ----
urls = pd.read_csv('dataset/balanced_urls.csv')  # adjust path as needed
X_urls, y_urls = urls['url'], urls['label']

X_train_u, X_test_u, y_train_u, y_test_u = train_test_split(
    X_urls, y_urls, test_size=0.2, random_state=42, stratify=y_urls
)

url_pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(3, 5),
        max_features=50_000  # tune this for memory/performance
    )),
    ('clf', LogisticRegression(
        max_iter=1000,
        class_weight='balanced',
        random_state=42
    ))
])

url_pipeline.fit(X_train_u, y_train_u)
print("=== URL Model ===")
print(classification_report(y_test_u, url_pipeline.predict(X_test_u)))

joblib.dump(url_pipeline, 'models/url_classifier.pkl')


# ---- 2) Windows CMD Classification ----
cmds = pd.read_excel('dataset/windows_cmd_analyzed.xlsx')  # adjust path as needed
numeric_cols = [
    'Lolbin (0.05)', 'Content (0.4)', 'Frequency (0.2)',
    'Source (0.1)', 'Network (0.1)', 'Behavioural (0.1)',
    'History (0.05)', 'Score'
]
text_col = 'prompt'

X_cmds = cmds[numeric_cols + [text_col]]
y_cmds = cmds['Label']

X_train_c, X_test_c, y_train_c, y_test_c = train_test_split(
    X_cmds, y_cmds, test_size=0.2, random_state=42, stratify=y_cmds
)

preprocessor = ColumnTransformer([
    ('txt', TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=10_000
    ), text_col),
    ('num', 'passthrough', numeric_cols)
])

cmd_pipeline = Pipeline([
    ('features', preprocessor),
    ('clf', RandomForestClassifier(
        n_estimators=200,
        class_weight='balanced',
        random_state=42
    ))
])

cmd_pipeline.fit(X_train_c, y_train_c)
print("\n=== CMD Model ===")
print(classification_report(y_test_c, cmd_pipeline.predict(X_test_c)))

joblib.dump(cmd_pipeline, 'models/cmd_classifier.pkl')
