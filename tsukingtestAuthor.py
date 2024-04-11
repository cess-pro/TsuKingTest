from scapy.all import *

def dns_response(pkt):
    if DNS in pkt and pkt[DNS].opcode == 0:  # 只处理标准查询
        queried_domain = pkt[DNS].qd.qname.decode()  # 提取查询的域名
        client_ip = pkt[IP].src  # 提取源 IP 地址
        client_port = pkt[UDP].sport  # 提取源端口
        print("[+] Get query from " + str(client_ip) + ":" + str(client_port) + "\t" +queried_domain)
        if ("rdtest.tsukingtest.dnssec.top" in queried_domain.lower()) or ("basetest.tsukingtest.dnssec.top" in queried_domain.lower()):
            # 构建 DNS 响应
            dns_response = IP(dst=client_ip, src=pkt[IP].dst)/UDP(dport=client_port, sport=53)/\
                        DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=queried_domain, ttl=10, rdata='127.0.0.1'))
            print("[-] answered")
            # 发送 DNS 响应
            send(dns_response, verbose=0)

#localip = input("Local IP Address to server: ")
localip = "202.112.51.96"
# 设置过滤器，只捕获 UDP 端口 53 的 DNS 请求
sniff(filter="dst host %s and port 53" % localip, prn=dns_response)