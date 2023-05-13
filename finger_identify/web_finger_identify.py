# -*- coding: utf-8 -*-

"""
@Tine: 2023/5/11 10:17
@Author: muddlelife
@File: web_finger_identify.py
@Description: Web服务的指纹识别
"""
import codecs
import random
from urllib.parse import urlsplit, urljoin
from queue import Queue
import json
import csv
import concurrent.futures
import mmh3
from lxml import etree
import requests
import urllib3

urllib3.disable_warnings()


def get_title(response_html):
    """从html中解析title字段"""
    html_obj = etree.HTML(response_html)
    try:
        title = html_obj.xpath('/html/head/title/text()')[0].strip().replace('\r', '').replace('\n',
                                                                                               '')
    except Exception:
        title = ''
    return title


class WebFingerIdentify:
    """
    Web指纹识别封装，去掉一切花里胡哨的东西
    """

    def __init__(self, web_url_list, pool_number=200):
        self.url_list = web_url_list
        self.pool_number = pool_number
        self.queue_result = Queue()

        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) '
            'Gecko/20100101 Firefox/68.0',
            'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/68.0'
        ]
        with open(r'finger.json', 'r', encoding='utf-8') as json_file:
            finger = json.load(json_file)
        self.finger_data_list = finger.get('fingerprint')  #

    def send_request(self, url):
        """通过requests库发送请求"""
        # 初始化
        headers = {
            "User-Agent": random.choice(self.user_agents)
        }
        try:
            response = requests.get(url, headers=headers, allow_redirects=True,
                                    timeout=10, verify=False)
            self.parse_data(url, response)
        except Exception:
            pass

    def parse_data(self, url, response):
        """从response中解析必要数据"""

        # 状态码
        response_code = response.status_code
        # 编码格式转换
        if response.encoding == 'ISO-8859-1':
            response.encoding = response.apparent_encoding
        response_html = response.text

        # title字段
        title = get_title(response_html)
        # server字段
        server = response.headers["Server"] if "Server" in response.headers else ""

        # icon_hash，这块返回的url为跳转后的url
        icon_hash = self.get_favicon_hash(response.url)
        cms = self.finger_identify(response_html, response.headers, icon_hash)

        data_result = {
            "url": url, "title": title, "status": response_code, "size": len(response_html),
            "cms": cms, "server": server, "icon_hash": icon_hash
        }
        self.queue_result.put(data_result)

    def get_favicon_hash(self, url):
        """获取icon_hash值"""

        headers = {
            "User-Agent": random.choice(self.user_agents)
        }
        try:
            parsed = urlsplit(url)
            url = urljoin(parsed.scheme + "://" + parsed.netloc, "favicon.ico")
            response = requests.get(url, headers=headers, timeout=4)
            favicon = codecs.encode(response.content, "base64")
            icon_hash = mmh3.hash(favicon)
            return icon_hash
        except Exception:
            return 0

    def finger_identify(self, response_html, response_header, icon_hash):
        """利用指纹库对响应结果进行识别"""
        for finger in self.finger_data_list:
            method = finger.get('method')
            location = finger.get('location')
            keyword = finger.get('keyword')
            # keyword and body
            if method == "keyword" and location == "body":
                if all(value in response_html for value in keyword):
                    return finger.get("cms")

            # keyword and headers
            if method == "keyword" and location == "header":
                headers_str = ' '.join(map(str, response_header.values()))
                if all(value in headers_str for value in keyword):
                    return finger.get("cms")

            if method == "faviconhash":
                if icon_hash == 0:
                    continue
                if keyword[0] == icon_hash:
                    return finger.get("cms")
            # regula 未实现，因为指纹库中没有该指纹，keyword中未找到正则表达式

        return ""

    def thread_pool(self):
        """创建线程池"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.pool_number) as pool:
            pool.map(self.send_request, self.url_list)

    def run(self):
        """调用方法实现指纹识别功能，返回结果为队列"""
        if self.thread_pool():
            return self.queue_result

        return self.queue_result

    def export_result_csv(self, file_path='result.csv'):
        """导出为csv文件"""
        # 指定要导出的字段
        fields = ['url', 'title', 'status', 'size', 'cms', 'server', 'icon_hash']

        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()  # 写入CSV文件的标题行
            while not self.queue_result.empty():
                writer.writerow(self.queue_result.get())


if __name__ == '__main__':
    with open(r'url.txt', 'r', encoding='utf-8') as file:
        url_list = [i.split("\n")[0] for i in file.readlines()]

    scan = WebFingerIdentify(url_list)
    scan.run()
    scan.export_result_csv()
