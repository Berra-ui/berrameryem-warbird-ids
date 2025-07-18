import logging
from scapy.all import sniff, IP, TCP
from sklearn.ensemble import IsolationForest
import numpy as np

# Log ayarları
logging.basicConfig(filename='ids_log.txt', level=logging.INFO, format='%(asctime)s %(message)s')

def log_event(event):
    logging.info(event)
    print(event)

packet_features = []

# Ağ paketi callback fonksiyonu
def packet_callback(packet):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        size = len(packet)
        feature = [sport, dport, size]
        packet_features.append(feature)
        log_event(f"Packet: {src}:{sport} -> {dst}:{dport} | Size: {size}")

if __name__ == "__main__":
    print("Ağ trafiği dinleniyor... (100 TCP paketi)")
    sniff(prn=packet_callback, count=100, filter="tcp", store=0)
    print("Dinleme tamamlandı. AI ile anomali analizi başlıyor...")

    # AI ile anomali tespiti
    if len(packet_features) > 10:
        X = np.array(packet_features)
        model = IsolationForest(contamination=0.1)
        preds = model.fit_predict(X)
        for i, pred in enumerate(preds):
            if pred == -1:
                log_event(f"ANOMALİ TESPİT EDİLDİ! Paket Özellikleri: {packet_features[i]}")
    else:
        print("Yeterli veri toplanamadı, anomali analizi atlandı.")

    print("Analiz tamamlandı. Sonuçlar ids_log.txt dosyasına kaydedildi.")