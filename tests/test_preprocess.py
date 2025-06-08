import pandas as pd
from src.preprocess import preprocess_pipeline

def test_preprocess_pipeline_creates_scaled_output():
    # Create temporary sample CSV
    df = pd.DataFrame({
        'duration': [1, 2],
        'protocol_type': ['tcp', 'udp'],
        'service': ['http', 'dns'],
        'src_bytes': [100, 200],
        'dst_bytes': [50, 80],
        'flag': ['SF', 'REJ'],
        'land': [0, 0],
        'wrong_fragment': [0, 0],
        'urgent': [0, 0],
        'label': ['normal', 'attack']
    })
    df.to_csv("tests/temp_test.csv", index=False)

    # Run preprocessing
    X, y = preprocess_pipeline("tests/temp_test.csv", ['protocol_type', 'flag'])

    assert X.shape[0] == 2
    assert len(y) == 2
    assert all(value in [0, 1] for value in y)
