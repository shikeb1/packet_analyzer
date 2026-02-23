from packet_analyzer.dpi_engine import DPIEngine
from packet_analyzer.rule_manager import RuleManager
from packet_analyzer.ml_model import MLClassifier

_model = None

def get_model():
    global _model
    if _model is None:
        _model = MLClassifier()
    return _model


def get_engine(input_file=None, output_file=None):
    rules = RuleManager()
    return DPIEngine(input_file, output_file, rules)