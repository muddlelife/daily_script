# -*- coding: utf-8 -*-

"""
@Tine: 2023/5/10 17:29
@Author: muddlelife
@File: one_scan_enough.py
@Description: 重新封装Masscan和Nmap，通过调用Masscan和Nmap实现端口扫描
"""

from queue import Queue

import csv
import random
import string
import os
import subprocess
import concurrent.futures
import nmap
import xmltodict


class OneScanFinsh():
    """
    封装Masscan和Nmap，通过先调用Masscan对目标IP进行端口扫描，然后扫描完成后，利用nmap进行服务识别
    """

    def __init__(self, ip_path, thread_number: int, masscan_path='masscan', rate='10000'):

        self.ip_path = ip_path
        # 生成masscan结果文件名
        self.masscan_result_file = ''.join(
            (random.choice(string.ascii_lowercase) for i in range(6))) + '.xml'
        self.thread_number = thread_number
        self.queue_result = Queue()
        self.masscan_path = masscan_path
        self.rate = rate

    def masscan_scan(self):
        """调用masscan扫描"""
        try:
            status, _ = subprocess.getstatusoutput(f"{self.masscan_path} --rate={self.rate} -p "
                                                   f"1-65535 -iL {self.ip_path} "
                                                   f"-oX {self.masscan_result_file}")
            if status == 0:
                return True
            return False
        except (ValueError, TypeError):
            return False

    def nmap_scan(self, masscan_info: dict):
        """调用nmap扫描"""
        try:
            host = masscan_info.get('host')
            port = masscan_info.get('port')

            nmap_obj = nmap.PortScanner()
            nmap_result = nmap_obj.scan(host, port, arguments="-sV -sT -Pn -T4 --host-timeout 60")

            tcp_data_dict = nmap_result['scan'][host]['tcp'][int(port)]
            protocol = tcp_data_dict.get('name')
            product = tcp_data_dict.get('product')
            version = tcp_data_dict.get('version')
            self.queue_result.put(
                {'host': host, 'port': port, 'protocol': protocol, 'product': product,
                 'version': version})
        except (ValueError, TypeError):
            pass

    def get_data_masscan(self):
        """从masscan中获取结果"""
        with open(self.masscan_result_file, 'r', encoding='utf-8') as file:
            xml_obj = xmltodict.parse(file.read())
            ip_line = xml_obj['nmaprun']['host']
            target_ip_port = []
            for line in ip_line:
                ip_address = line['address']['@addr']
                port = line['ports']['port']['@portid']
                target_ip_port.append({'host': ip_address, 'port': str(port)})
        os.system(f'rm {self.masscan_result_file}')
        return target_ip_port

    def thread_pool(self, target_ip_port):
        """线程池,调用nmap进行端口识别"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_number) as pool:
            pool.map(self.nmap_scan, target_ip_port)

    def run(self):
        """上述方法调用实现masscan+nmap扫描，输出结果为队列"""
        if self.masscan_scan():
            target_ip_port = self.get_data_masscan()
            self.thread_pool(target_ip_port)
            return self.queue_result

        return self.queue_result

    def export_result_csv(self, file_path='result.csv'):
        """导出为csv文件"""
        # 指定要导出的字段
        fields = ['host', 'port', 'protocol', 'product', 'version']

        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()  # 写入CSV文件的标题行
            while not self.queue_result.empty():
                writer.writerow(self.queue_result.get())


if __name__ == '__main__':
    scan = OneScanFinsh('./data/ip.txt', 200)  # 创建对象
    scan.run()  # 执行扫描
    scan.export_result_csv()  # 导出csv文件
