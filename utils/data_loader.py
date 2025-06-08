import pandas as pd
import json

def load_feature_config(path='utils/feature_config.json'):
    with open(path, 'r') as f:
        return json.load(f)

def load_dataset(path, config_path='utils/feature_config.json'):
    config = load_feature_config(config_path)
    df = pd.read_csv(path)
    df = df.dropna()
    features = config["features"]
    label = config["label"]
    return df[features], df[label]
