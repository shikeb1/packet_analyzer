import pickle
import numpy as np
from .types import AppType

class MLClassifier:
    def __init__(self, model_path="ml/model.pkl"):
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)
        self.int_to_app = {i: app for i, app in enumerate(AppType)}

    def predict(self, flow_features):
        probs = self.model.predict_proba([flow_features])[0]
        pred_class = np.argmax(probs)
        confidence = probs[pred_class]
        return self.int_to_app[pred_class], confidence