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
import nmap
import xmltodict
import subprocess
import concurrent.futures


class OneScanFinsh(object):
    """
    封装Masscan和Nmap，通过先调用Masscan对目标IP进行端口扫描，然后扫描完成后，利用nmap进行服务识别
    """

    def __init__(self, ip_path, thread_number: int, masscan_path='masscan', rate='10000', port='1-65535'):

        self.ip_path = ip_path
        # 生成masscan结果文件名
        self.masscan_result_file = ''.join((random.choice(string.ascii_lowercase) for i in range(6))) + '.xml'
        self.thread_number = thread_number
        self.queue_result = Queue()
        self.masscan_path = masscan_path
        self.rate = rate
        self.port = port

    def masscan_scan(self):
        """调用masscan扫描"""
        try:
            status, result = subprocess.getstatusoutput(
                "{} --rate={} -p {} -iL {} -oX {}".format(self.masscan_path, self.rate, self.port, self.ip_path,
                                                          self.masscan_result_file))
            if status == 0:
                return True
            else:
                return False
        except Exception as e:
            return False

    def nmap_scan(self, masscan_info: dict):
        """调用nmap扫描"""
        try:
            host = masscan_info.get('host')
            port = masscan_info.get('port')

            nm = nmap.PortScanner()
            nmap_result = nm.scan(host, port, arguments="-sV -sT -Pn -T4 --host-timeout 60")

            tcp_data_dict = nmap_result['scan'][host]['tcp'][int(port)]
            protocol = tcp_data_dict.get('name')
            product = tcp_data_dict.get('product')
            version = tcp_data_dict.get('version')
            self.queue_result.put(
                {'host': host, 'port': port, 'protocol': protocol, 'product': product, 'version': version})
        except Exception as e:
            pass

    def get_data_masscan(self):
        """从masscan中获取结果"""
        with open(self.masscan_result_file, 'r') as f:
            xml_obj = xmltodict.parse(f.read())
            ip_line = xml_obj['nmaprun']['host']
            target_ip_port = []
            for line in ip_line:
                ip = line['address']['@addr']
                port = line['ports']['port']['@portid']
                target_ip_port.append({'host': ip, 'port': str(port)})
        os.system('rm {}'.format(self.masscan_result_file))
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
        else:
            return self.queue_result

    def export_result_csv(self, file_path='result.csv'):
        """导出为csv文件"""
        # 指定要导出的字段
        fields = ['host', 'port', 'protocol', 'product', 'version']

        with open(file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()  # 写入CSV文件的标题行
            while not self.queue_result.empty():
                writer.writerow(self.queue_result.get())


if __name__ == '__main__':
    nmap_result = OneScanFinsh('./data/ip.txt', 200)  # 创建对象
    nmap_result.run()  # 执行扫描
    nmap_result.export_result_csv()  # 导出csv文件
