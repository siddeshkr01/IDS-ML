import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

def encode_categorical(df, categorical_columns, le_dict=None):
    if le_dict is None:
        le_dict = {}
        for col in categorical_columns:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            le_dict[col] = le
    else:
        for col in categorical_columns:
            le = le_dict[col]
            df[col] = le.transform(df[col])
    return df, le_dict

def scale_features(X, scaler=None):
    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)
    return pd.DataFrame(X_scaled, columns=X.columns), scaler

def preprocess_pipeline(df, categorical_columns, scaler=None, le_dict=None):
    df = df.copy()
    df, le_dict = encode_categorical(df, categorical_columns, le_dict)
    X = df.drop('label', axis=1)
    y = df['label'] if 'label' in df.columns else None
    X_scaled, scaler = scale_features(X, scaler)
    return X_scaled, y, scaler, le_dict
