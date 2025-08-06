#!/usr/bin/env python3
"""
Python script to find WISE-4050 devices on the network
"""

import socket
import threading
import requests
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_local_ip():
    """Get the local IP address of this machine"""
    try:
        # Connect to a remote address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return None

def get_network_range(ip):
    """Get the network range from an IP address"""
    try:
        # Assume /24 subnet (most common for home networks)
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network.network_address)[:-1]  # Remove the .0
    except:
        return None

def ping_host(ip):
    """Check if a host is alive using socket connection"""
    try:
        # Try to connect to port 80 (HTTP) with a short timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 80))
        sock.close()
        
        if result == 0:
            return ip
        
        # Also try port 443 (HTTPS)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, 443))
        sock.close()
        
        if result == 0:
            return ip
            
    except:
        pass
    return None

def check_web_interface(ip):
    """Check if the device has a web interface and try to identify it"""
    try:
        # Try HTTP first
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{ip}"
                response = requests.get(url, timeout=3)
                
                content = response.text.lower()
                title = ""
                
                # Extract title
                if '<title>' in content:
                    title = content.split('<title>')[1].split('</title>')[0]
                
                # Look for WISE or Advantech indicators
                indicators = ['wise', 'advantech', 'daq', 'industrial', 'modbus', 'mqtt']
                found_indicators = [indicator for indicator in indicators if indicator in content]
                
                return {
                    'ip': ip,
                    'protocol': protocol,
                    'status_code': response.status_code,
                    'title': title,
                    'indicators': found_indicators,
                    'likely_wise': len(found_indicators) > 0 or 'wise' in content
                }
            except requests.exceptions.SSLError:
                continue
            except:
                continue
    except:
        pass
    return None

def scan_network():
    """Scan the local network for devices"""
    print("🔍 Finding your network configuration...")
    
    local_ip = get_local_ip()
    if not local_ip:
        print("❌ Could not determine local IP address")
        return
    
    print(f"📍 Your Raspberry Pi IP: {local_ip}")
    
    network_base = get_network_range(local_ip)
    if not network_base:
        print("❌ Could not determine network range")
        return
    
    print(f"🌐 Scanning network range: {network_base}1-254")
    print("⏳ This may take a minute...")
    
    # Generate list of IPs to scan
    ips_to_scan = [f"{network_base}{i}" for i in range(1, 255)]
    
    alive_hosts = []
    
    # Ping sweep with threading
    print("\n📶 Step 1: Finding live hosts...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in ips_to_scan}
        
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                alive_hosts.append(result)
                print(f"  ✅ Found live host: {result}")
    
    if not alive_hosts:
        print("❌ No live hosts found on the network")
        return
    
    print(f"\n🎯 Step 2: Checking {len(alive_hosts)} live hosts for web interfaces...")
    
    web_devices = []
    potential_wise = []
    
    # Check web interfaces
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(check_web_interface, ip): ip for ip in alive_hosts}
        
        for future in as_completed(future_to_ip):
            result = future.result()
            if result:
                web_devices.append(result)
                if result['likely_wise']:
                    potential_wise.append(result)
                print(f"  🌐 Web interface found: {result['protocol']}://{result['ip']} - {result['title']}")
    
    # Display results
    print("\n" + "="*60)
    print("📊 SCAN RESULTS")
    print("="*60)
    
    if potential_wise:
        print("🎯 POTENTIAL WISE-4050 DEVICES:")
        for device in potential_wise:
            print(f"  🔥 {device['protocol']}://{device['ip']}")
            print(f"     Title: {device['title']}")
            print(f"     Indicators: {', '.join(device['indicators'])}")
            print()
    
    if web_devices:
        print("🌐 ALL DEVICES WITH WEB INTERFACES:")
        for device in web_devices:
            indicator = "🔥" if device['likely_wise'] else "📄"
            print(f"  {indicator} {device['protocol']}://{device['ip']} - {device['title']}")
    
    print("\n💡 NEXT STEPS:")
    if potential_wise:
        print("1. Try accessing the URLs marked with 🔥 first")
        print("2. Look for MQTT or IoT configuration options")
        print("3. The default username/password is often admin/admin")
    else:
        print("1. Try accessing each web interface manually")
        print("2. Look for industrial-looking interfaces")
        print("3. WISE devices may not have been detected automatically")
    
    print(f"\n📝 Your Pi's IP (for MQTT broker): {local_ip}")

def test_specific_ip():
    """Test a specific IP address provided by user"""
    while True:
        ip = input("\n🎯 Enter an IP address to test (or 'scan' to scan network, 'quit' to exit): ").strip()
        
        if ip.lower() == 'quit':
            break
        elif ip.lower() == 'scan':
            scan_network()
            continue
        
        try:
            # Validate IP
            ipaddress.IPv4Address(ip)
            
            print(f"🔍 Testing {ip}...")
            
            # Check if alive
            if ping_host(ip):
                print(f"  ✅ Host is alive")
                
                # Check web interface
                result = check_web_interface(ip)
                if result:
                    print(f"  🌐 Web interface: {result['protocol']}://{ip}")
                    print(f"  📄 Title: {result['title']}")
                    if result['indicators']:
                        print(f"  🎯 Found indicators: {', '.join(result['indicators'])}")
                    if result['likely_wise']:
                        print("  🔥 This looks like it could be your WISE device!")
                else:
                    print("  ❌ No web interface found")
            else:
                print(f"  ❌ Host not responding")
                
        except ValueError:
            print("  ❌ Invalid IP address format")

if __name__ == "__main__":
    print("🔍 WISE-4050 Network Scanner")
    print("="*40)
    
    while True:
        print("\nChoose an option:")
        print("1. Auto-scan network")
        print("2. Test specific IP")
        print("3. Quit")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            scan_network()
        elif choice == '2':
            test_specific_ip()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
