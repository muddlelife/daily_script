# -*- coding: utf-8 -*-

"""
@Tine: 2023/5/10 22:12
@Author: muddlelife
@File: dns_shoot.py
@Description: 将域名进行指定DNS服务器进行解析，分析DNS服务器的响应时间，从而判断DNS服务器的优劣
"""
from queue import Queue
from random import sample
import concurrent.futures
import time
from tqdm import tqdm
import dns.resolver


result = Queue()
RANDOM_NUM = 10000


# 时间装饰器
def calculate_time(func):
    """计算程序运行时间"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        func(*args, **kwargs)
        end_time = time.time()
        print(f"程序运行时间为: {round(end_time - start_time, 2)}秒")
        return result

    return wrapper


def dns_parse(dns_info: dict):
    """DNS解析函数"""
    dns_ip = dns_info.get('dns_ip')
    domain = dns_info.get('domain')

    resolver = dns.resolver.Resolver(configure=False)  # 不读取系统的DNS配置文件
    resolver.cache = None
    # 超时时间
    resolver.lifetime = 5
    resolver.cache = dns.resolver.LRUCache()
    resolver.nameservers = [dns_ip]

    spend_time = dns_parse_children(resolver, domain)
    result.put(spend_time)


@calculate_time
def thread_pool(domain_info_list: list, thread_number=200):
    """线程池调用DNS解析函数，生成进度条"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_number) as pool:
        future_list = [pool.submit(dns_parse, data) for data in domain_info_list]

        # 显示进度条
        for future in tqdm(concurrent.futures.as_completed(future_list), total=len(future_list)):
            future.result()


# 生成存有列表以及dns地址的列表
def get_domain_info_list(domain_list, dns_ip):
    """生成域名信息列表"""
    domain_list_info = []
    for domain in domain_list:
        domain_list_info.append({'domain': domain, 'dns_ip': dns_ip})

    return domain_list_info


def dns_parse_children(resolver, domain):
    """计算DNS解析时间"""
    try:
        start_time = time.time()
        resolver.resolve(domain, 'A')
        return (time.time() - start_time) * 1000
    except Exception:
        return 0


def get_random_list(domain_path):
    """随机从bigdomains.txt选取域名，增加实验准确度"""
    with open(domain_path, 'r',encoding='utf-8') as file:
        domain_list = [i.split('\n')[0] for i in file.readlines()]
    randon_list = sample(domain_list, RANDOM_NUM)
    return randon_list


def main(name, random_list, dns_ip):
    """主程序"""
    domain_list_info = get_domain_info_list(random_list, dns_ip)
    thread_pool(domain_list_info)

    success_number = 0
    all_time = 0
    while not result.empty():
        spend_time = result.get()
        if spend_time != 0:
            success_number = success_number + 1
            all_time = all_time + spend_time

    if success_number == 0:
        print(f"{name} dns：{dns_ip} 域名总数：{len(domain_list_info)} "
              f"成功解析个数：{success_number} 平均响应时间：0 解析成功率: 0%")
    else:
        average_time = all_time / success_number
        print(f"{name} dns：{dns_ip} 域名总数：{len(domain_list_info)} 成功解析个数：{success_number} "
              f"平均响应时间：{str(round(average_time, 2))}毫秒 "
              f"解析成功率：{success_number / len(domain_list_info):.2%}")


if __name__ == '__main__':

    DOMAIN_FILE = 'bigdomains.txt'
    aliyun_dns_ip = ['223.5.5.5', '223.6.6.6']
    one_dns_ip = ['114.114.114.114']

    random_domain_list = get_random_list(DOMAIN_FILE)

    print("开始执行阿里云DNS")
    for i in aliyun_dns_ip:
        main('阿里云DNS', random_domain_list, i)

    print("开始执行114DNS")
    for i in one_dns_ip:
        main('114DNS', random_domain_list, i)
