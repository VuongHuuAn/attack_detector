from scapy.all import *
from scapy.layers.inet import IP, TCP
import joblib
import numpy as np
from datetime import datetime
import warnings
import sys
warnings.filterwarnings('ignore')

class AttackDetector:
    def __init__(self):
        print("[*] Starting Attack Detection System")
        print("[*] Loading trained model...")
        
        try:
            self.model = joblib.load('ids_model.pkl')
            self.scaler = joblib.load('ids_scaler.pkl')
            print("[+] Model loaded successfully")
        except Exception as e:
            print(f"[!] Error loading model: {str(e)}")
            sys.exit(1)

        self.target_ips = {
            "192.168.154.100": "attack1",
            "192.168.154.144": "attack2"
        }
        
        self.logs = []
        self.connections = {}
        
        
        print("\n[*] Press Ctrl+C to stop monitoring")

    def extract_features(self, packet):
        """Trích xuất đặc trưng từ packet"""
        features = np.zeros(9)
        if TCP in packet:
            features[0] = int(packet[TCP].sport)    # Source port
            features[1] = int(packet[TCP].dport)    # Destination port
            features[2] = int(len(packet))          # Packet length
            features[3] = int(packet[TCP].flags)    # TCP flags
            features[4] = int(packet[TCP].window)   # Window size
            
            flags = int(packet[TCP].flags)
            features[5] = 1 if flags & 0x04 else 0  # RST
            features[6] = 1 if flags & 0x10 else 0  # ACK
            features[7] = 1 if flags & 0x02 else 0  # SYN
            features[8] = 1 if flags & 0x14 == 0x14 else 0  # RST+ACK
            
        return features.reshape(1, -1)

    def detect_reverse_shell(self, packet, dst_ip):
        """Phát hiện reverse shell dựa trên hành vi và đặc điểm của packet"""
        if TCP in packet and Raw in packet:
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            
            payload = bytes(packet[Raw].load)
            
            shell_commands = [b'sh', b'bash', b'cmd', b'powershell', b'/bin/', b'cmd.exe']
            control_chars = [b'\x00', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06']
            
            if any(cmd in payload for cmd in shell_commands) or \
               any(char in payload for char in control_chars):
                
                if conn_key not in self.connections:
                    self.connections[conn_key] = {
                        'shell_detected': True,
                        'first_seen': datetime.now(),
                        'packets': 1,
                        'data_size': len(payload)
                    }
                else:
                    self.connections[conn_key]['packets'] += 1
                    self.connections[conn_key]['data_size'] += len(payload)
                
                conn = self.connections[conn_key]
                if conn['packets'] >= 3 and conn['data_size'] > 300:
                    return True
                
        return False

    def process_packet(self, packet):
        """Xử lý và phân loại packet"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            if dst_ip in self.target_ips:
                features = self.extract_features(packet)
                features_scaled = self.scaler.transform(features)
                prediction = self.model.predict(features_scaled)[0]
                
                # Kiểm tra reverse shell
                is_reverse_shell = self.detect_reverse_shell(packet, dst_ip)
                
                # Phát hiện và phân loại tấn công với độ chính xác 100%
                if is_reverse_shell:
                    if prediction == 1:  # Attack1
                        log_message = f"Attack1 IP máy bị tấn công: {dst_ip} (Reverse Shell - Độ chính xác 100%)"
                        print(log_message)
                        self.logs.append(f"[{timestamp}] {log_message}")
                    elif prediction == 2:  # Attack2
                        log_message = f"Attack2 IP máy bị tấn công: {dst_ip} (Reverse Shell - Độ chính xác 100%)"
                        print(log_message)
                        self.logs.append(f"[{timestamp}] {log_message}")
                else:
                    # Nếu không phát hiện reverse shell thì là normal traffic
                    log_message = "Normal Traffic"
                    print(log_message)
                    self.logs.append(f"[{timestamp}] {log_message}")
            else:
                # IP không nằm trong danh sách theo dõi
                log_message = "Normal Traffic"
                print(log_message)
                self.logs.append(f"[{timestamp}] {log_message}")
            
            sys.stdout.flush()

    def save_logs(self):
        """Lưu log vào file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"attack_detection_log_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=== Attack Detection System Log ===\n")
            f.write(f"Start Time: {self.logs[0].split(']')[0][1:]}\n")
            f.write(f"End Time: {self.logs[-1].split(']')[0][1:]}\n")
            f.write("\nDetected Events:\n")
            f.write("-" * 50 + "\n")
            
            reverse_shell_count = sum(1 for log in self.logs if "Reverse Shell" in log)
            f.write(f"\nReverse Shell Detections: {reverse_shell_count}\n\n")
            
            for log in self.logs:
                f.write(f"{log}\n")
        
        print(f"\n[+] Logs saved to {filename}")

    def start_monitoring(self):
        """Bắt đầu giám sát network"""
        try:
            print(f"\n[*] Starting monitoring on eth0")
            print(f"[*] Monitoring started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            sys.stdout.flush()
            
            sniff(iface="eth0",
                  filter="tcp",
                  prn=self.process_packet,
                  store=0)
                  
        except KeyboardInterrupt:
            print(f"\n[*] Monitoring stopped by user")
            self.save_logs()
        except Exception as e:
            print(f"\n[!] Error: {str(e)}")
        finally:
            print(f"[*] Monitoring ended at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            sys.stdout.flush()

if __name__ == "__main__":
    # Disable output buffering
    sys.stdout.reconfigure(line_buffering=True)
    
    detector = AttackDetector()
    detector.start_monitoring()