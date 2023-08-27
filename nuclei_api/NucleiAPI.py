# -*- coding: utf-8 -*-

"""
@Tine: 2023/8/27 16:27
@Author: muddlelife
@File: NucleiAPI
@Description: Ncueli API调用
"""

import subprocess
import datetime


def time_stamp():
    """时间戳"""
    current_datetime = datetime.datetime.now()
    return current_datetime.strftime("%Y-%m-%d %H:%M:%S")


def parse_data(process):
    stdout, stderr = process.communicate()
    result = []
    try:
        info = stdout.decode().split('\n')[0:-1]
        for i in info:
            tmp = i[1:]
            a = tmp.split('] [')
            b = a[2].split('] ')
            item = {
                "vulnerability": a[0],
                "severity": b[0],
                "poc_url": b[-1]
            }
            result.append(item)
    except Exception as e:
        print(e)
    return result


class NucleiAPI:
    """封装NucleiAPI"""

    def __init__(self):
        self.startup = 'nuclei -duc -stream -silent -nc'

    def scan(self, url, template_id):
        """指定模版ID进行扫描"""
        result = {'url': url, 'template_id': template_id}
        process = subprocess.Popen('{} -u {} -id {}'.format(self.startup, url, template_id), shell=True,
                                   stdout=subprocess.PIPE, close_fds=True, stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        scan_result = parse_data(process)

        result['data'] = scan_result
        result['time_stamp'] = time_stamp()

        return result


if __name__ == '__main__':
    result = NucleiAPI().scan('http://106.52.50.243:8000', 'kingdee-k3cloud-arbitrary-file-read')
    print(result)
