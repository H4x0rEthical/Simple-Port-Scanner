import socket
import threading
from scapy.all import TCP, sr1, IP


print("\033[32m" + r"""
____   ___   ____  ______       _____   __   ____  ____   ____     ___  ____  
|    \ /   \ |    \|      |     / ___/  /  ] /    ||    \ |    \   /  _]|    \ 
|  o  )     ||  D  )      |    (   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
|   _/|  O  ||    /|_|  |_|     \__  |/  /  |     ||  |  ||  |  ||    _]|    / 
|  |  |     ||    \  |  |       /  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \ 
|  |  |     ||  .  \ |  |       \    \     ||  |  ||  |  ||  |  ||     ||  .  \
|__|   \___/ |__|\_| |__|        \___|\____||__|__||__|__||__|__||_____||__|\_|
                                                                               
""")

print("IGNORE THE ERRORS OR WARNINGS!")
print("HalfTcpScan is way slower")
print("1. FullTcpScan\n2. HalfTcpScan(Stealthy)")

#--------------------------------------------------------------------------------#
Choice = input("\n\n\nEnter your choice: ")
Ports = list(range(0, 8001))
Host = input("Enter the host here: ")
lock = threading.Lock()

#Functions
def FULLTCPSCAN(Host, Port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((Host, Port))
            if result == 0:
                with lock:
                    print(f"Open port: {Port}")
    
    except socket.timeout:
            pass

    except Exception as e:
        with lock:
            print(Exception, e)


def HalfTCPScan(port):
     ip = IP(dst=Host)
     tcp = TCP(dport=port, flags="S")
     packet = ip / tcp

     response = sr1(packet, timeout=2, verbose=0)

     if response:
        try:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    print(f"\033[32mPort {port} is OPEN\033[0m")
               
                    rst_pkt = IP(dst=Host)/TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=1, verbose=0)
                elif response[TCP].flags == 0x14:
                    pass
                else:
                    print(f"\033[33mPort {port} is FILTERED (ICMP error)\033[0m")

        except Exception as e:
            print(Exception, e)

            



match Choice:
        case "1":
            Threads = []
            for port in Ports:
                Thread1 = threading.Thread(target=FULLTCPSCAN, args=(Host, port))
                Threads.append(Thread1)
                Thread1.start()

            for thread in Threads:
                 thread.join()
        case "2":
               for port in Ports:
                    HalfTCPScan(port)
            