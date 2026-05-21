from scapy.all import *
base_ip=input("enter the base ip which doesnt chnage with device in your network for eg--> 192.168.1")
for last_octet in range(1, 255):
    target_ip = f"{base_ip}{last_octet}"
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered, unanswered = srp(request, timeout=0.2, verbose=False)
    port_list = [80, 443, 53]# list of ports to scan 
    port_approved = []
    
    #checks if host is live 
    if len(answered) > 0:
        live_mac = answered[0][1].hwsrc
        print(f"\n[+] Live Host Identified: {target_ip} -> MAC: {live_mac}")#prints the mac adress with ip adress
        
        for i in port_list:
           
            packet = sr1(IP(dst=target_ip) / TCP(dport=i, flags="S"), timeout=0.5, verbose=False)
            
            if packet is not None and packet.haslayer(TCP):
                
                if packet[TCP].flags == 0x12:
                    port_approved.append(i)
                    
                    # Clean up the connection footprint cleanly with a Reset
                    sr1(IP(dst=target_ip) / TCP(dport=i, flags="R"), timeout=0.5, verbose=False)
                    
        print(f"    -> Discovered Open Ports: {port_approved}")