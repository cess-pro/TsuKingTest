import dns.message
import dns.query
import time
import random
import string
import statistics
import numpy as np

# ANSI 转义码定义不同颜色和样式
class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def get_resolver_time(query_message, dns_resolver):
    # 开始计时
    start_time = time.time()
    try:
        # 发送非递归DNS查询请求
        response = dns.query.udp(query_message, dns_resolver, timeout=5)
        end_time = time.time()
        request_duration = end_time - start_time
        # 处理响应
        if response.rcode() == dns.rcode.NOERROR:
            answer = response.answer
            for rrset in answer:
                for record in rrset:
                    return (str(record), None, request_duration)
            return(None, None, request_duration)
        else:
            end_time = time.time()
            request_duration = end_time - start_time
            return (None,f"DNS查询返回错误码：{response.rcode()}", request_duration)
    except dns.exception.Timeout:
        end_time = time.time()
        request_duration = end_time - start_time
        return(None, "DNS查询超时", request_duration)

    except dns.query.BadResponse:
        end_time = time.time()
        request_duration = end_time - start_time
        return(None,"收到无效的DNS响应",request_duration)

    except Exception as e:
        end_time = time.time()
        request_duration = end_time - start_time
        return(None, f"DNS查询过程中发生错误：{e}", request_duration)

    

def generate_random_string(length):
    # 定义可能的字符集
    characters = string.ascii_letters + string.digits
    
    # 使用random.choices从字符集中选择指定数量的随机字符
    random_string = ''.join(random.choices(characters, k=length))
    
    return random_string


dns_resolver = "223.5.5.5"
print(color.YELLOW,"[+]获取基准耗时...",color.END)
base_duration = 0
tmp_timeuse = []
target_domain = generate_random_string(6)+".basetest.tsukingtest.dnssec.top"
query_message = dns.message.make_query(target_domain, 'A', want_dnssec=False)
anser, error, request_duration = get_resolver_time(query_message, dns_resolver)
print(color.CYAN,"[+++++]{获取结果:%s}{遇到错误:%s}{耗时:%f秒}" % (anser, error, request_duration), color.END)
if error:
    print(color.YELLOW,"[+++++]获取基准耗时失败，退出测试，请确认所测试解析器可用",color.END)
    exit(1)
for i in range(5): 
    query_message = dns.message.make_query(target_domain, 'A', want_dnssec=False)
    anser, error, request_duration = get_resolver_time(query_message, dns_resolver)
    tmp_timeuse.append(request_duration)
    print(color.CYAN,"[+++++]{获取结果:%s}{遇到错误:%s}{耗时:%f秒}" % (anser, error, request_duration), color.END)
base_duration = statistics.mean(tmp_timeuse)
print(color.YELLOW,"[+]基准耗时:", base_duration, "秒",color.END)


# 测试RD规范
print(color.YELLOW,"[+]开始测试RD规范...",color.END)
rd_test = True
target_domain = generate_random_string(6)+".rdtest.tsukingtest.dnssec.top"
query_message = dns.message.make_query(target_domain, 'A', want_dnssec=False)
query_message.flags &= ~dns.flags.RD  # 清除RD标志位
anser, error, request_duration = get_resolver_time(query_message, dns_resolver)
print(color.CYAN,"[+++++]{获取结果:%s}{遇到错误:%s}{耗时:%f秒}" % (anser, error, request_duration), color.END)
if anser:
    rd_test = False
    print(color.RED,"[+]RD规范不符合",color.END)
else:
    print(color.GREEN,"[+]RD规范符合",color.END)
    print(color.GREEN,"[+]不存在TsuKing风险",color.END)
    exit(0)

## 测试负缓存
print(color.YELLOW,"[+]开始测试负缓存...",color.END)
nage_cache_test = True
tims_use = []
for i in range(10):
    target_domain = generate_random_string(6)+str(i)+"neg.tsukingtest.dnssec.top"
    query_message = dns.message.make_query(target_domain, 'A', want_dnssec=False)
    anser, error, request_duration = get_resolver_time(query_message, dns_resolver)
    tims_use.append(request_duration)
    print(color.CYAN,"[+++++]{获取结果:%s}{遇到错误:%s}{耗时:%f秒}" % (anser, error, request_duration), color.END)

if np.median(tims_use) >= (2 * base_duration):
    nage_cache_test = False
    print(color.RED,"[+++++]负缓存不完整",color.END)
else:
    print(color.GREEN,"[+++++]负缓存完整",color.END)

if (not rd_test) and (not nage_cache_test):
    print(color.RED,"[+]存在TsuKing风险",color.END)
else:
    print(color.GREEN,"[+]不存在TsuKing风险",color.END)