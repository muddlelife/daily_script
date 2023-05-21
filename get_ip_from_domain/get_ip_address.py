# -*- coding: utf-8 -*-

"""
@Tine: 2023/5/21 09:26
@Author: muddlelife
@File: get_ip_address.py
@Description: 通过域名获取IP
"""
import concurrent.futures
import ipaddress
from queue import Queue
import dns.resolver


class GetIpAddress:
    """实现一个通过域名获取IP"""

    def __init__(self, domains_list):
        self.dns_server = '223.5.5.5'
        self.domain_list = domains_list
        self.queue_result = Queue()
        self.thread_number = 200

    def get_ip_address(self, domain):
        """通过解析域名获取ip"""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        resolver.nameservers = [self.dns_server]
        try:
            answer = resolver.resolve(domain, 'A')
            ip_address = answer[0].address
            self.queue_result.put(ip_address)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass

    def thread_pool(self):
        """多线程获取IP地址，提高效率"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_number) as pool:
            pool.map(self.get_ip_address, self.domain_list)

    def export_result(self):
        """导出IP地址到txt文件中，并去重并排序，便于后面补C段"""
        ip_list = []
        while not self.queue_result.empty():
            ip_list.append(self.queue_result.get())

        sorted_ips = sorted([ipaddress.ip_address(ip) for ip in set(ip_list)])
        # 去重
        with open(r'result.txt', 'w', encoding='utf-8') as file:
            for ip_address in sorted_ips:
                file.write(str(ip_address) + '\n')


if __name__ == '__main__':
    with open(r'domains.txt', 'r', encoding='utf-8') as domain_file:
        domain_list = [domain.split('\n')[0] for domain in domain_file.readlines()]

    # 运行使用
    obj = GetIpAddress(domain_list)
    obj.thread_pool()
    obj.export_result()
