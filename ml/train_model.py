import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import glob
import os
from scapy.all import rdpcap
from packet_analyzer.packet_parser import parse_packet
from packet_analyzer.connection_tracker import ConnectionTracker
from packet_analyzer.types import AppType
from feature_extraction import extract_flow_features

def load_labeled_flows(pcap_files, labels):
    X = []
    y = []
    for file_path, label in zip(pcap_files, labels):
        tracker = ConnectionTracker()
        packets = rdpcap(file_path)
        for pkt in packets:
            parsed = parse_packet(pkt)
            if not parsed:
                continue
            ft = parsed['five_tuple']
            flow = tracker.get_or_create_flow(ft)
            if not hasattr(flow, 'packets'):
                flow.packets = []
            flow.packets.append(parsed)
        for ft, flow in tracker.flows.items():
            if len(flow.packets) < 2:
                continue
            feats = extract_flow_features(flow.packets)
            if feats is not None:
                X.append(feats)
                y.append(label.value)
    return np.array(X), np.array(y)

if name == "__main__":
    # Example: you need to have labeled pcap files in a folder
    # This is just a placeholder; you must provide actual data.
    pcap_files = glob.glob("./data/*.pcap")
    labels = []  # map filename to AppType value
    # For demonstration, we'll create dummy data
    X = np.random.rand(100, 9)
    y = np.random.randint(0, len(AppType), 100)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))
    with open("ml/model.pkl", "wb") as f:
        pickle.dump(clf, f)