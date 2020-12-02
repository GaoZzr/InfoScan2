# -*- coding: utf-8 -*
import argparse
from utils.crt import *
from utils.yumingco import Yumingco
from utils.ip138 import Ip138
from utils.hackertarget import Hackertarget
from utils.virusTotal import Virus
from utils.cesuyun import Cesuyun
from utils.cunhuo import Cunhuo_domain
from utils.jsfinder import Jsfinder
from utils.waf import WAF
from utils.common import *
import sys
db = connet()
def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -u http://www.baidu.com")
    parser.add_argument("-u", "--url", help="The subdomain")
    parser.add_argument("-f", "--file", help="The subdomain file ")
    parser.add_argument('-w', "--waf",action='store_true',help='waf detection')
    parser.add_argument("-j", "--js", action="store_true",help='js find')
    return parser.parse_args()

# 接受用户输入的域名，调用InfoScan
def InfoScan(url):
    url = Url(url)  # 处理域名
    logger.log('INFOR',"当前域名:"+get_domain_root(url))
    result1 = Crt(domain=get_domain_root(url)).run()
    result2 = Yumingco(domain=get_domain_root(url)).run()
    result3 = Ip138(domain=get_domain_root(url)).run()
    result4 = Hackertarget(domain=get_domain_root(url)).run()
    result5 = Virus(domain=get_domain_root(url)).run()
    result6 = Cesuyun(domain=get_domain_root(url)).run()

    # 将所有列表合并，方便去重整理结果
    result_end(result1)  # crt查询结果
    result_end(result2)  # yumingco查询结果
    result_end(result3)  # ip138查询结果
    result_end(result4)  # hackertarget查询结果
    result_end(result5)  # virustotal查询
    result_end(result6)  # Cesuyun查询
    result_chaxun = list(set(resultall))  # 去重后的结果

    #print_result(result_chaxun)
    Baocun(url, result_chaxun)
    print_try("共收集"+str(len(result_chaxun))+"个子域名\n")
    resultall.clear()

# 判断是否存活
def Cunhuo(url):
    Cunhuo_domain(file=get_domain_root(url)).run(get_domain_root(url))

# 使用jsfinder进行爬取js文件
def JsFinder(url):
    Jsfinder(file=get_domain_root(url),a = 'cunhuo_url',b=1).run()

def JsFinder2(url):
    Jsfinder(file=get_domain_root(url),a = 'cunhuo_url_no_waf',b=2).run()

def Waf(url):
    WAF(file = get_domain_root(url)).run(get_domain_root(url))

if __name__ == '__main__':
    #InfoScan('runoob.com')
    args = parse_args()
    if args.file == None:
        if args.waf is not True:
            if args.js is not True:
                urls = args.url
                InfoScan(urls)
                Cunhuo(urls)
            else:
                urls = args.url
                InfoScan(urls)
                Cunhuo(urls)
                JsFinder(urls)
        elif args.js is not True:
            urls = args.url
            InfoScan(urls)
            Cunhuo(urls)
            Waf(urls)
        else:
            urls = args.url
            InfoScan(urls)
            Cunhuo(urls)
            Waf(urls)
            JsFinder2(urls)

    else:
        file = args.file
        for url in open(file):
            #print(url)
            if args.waf is not True:
                if args.js is not True:
                    urls = url.replace('\n','')
                    InfoScan(urls)
                    Cunhuo(urls)
                else:
                    urls = url.replace('\n','')
                    InfoScan(urls)
                    Cunhuo(urls)
                    JsFinder(urls)
            elif args.js is not True:
                urls = url.replace('\n','')
                InfoScan(urls)
                Cunhuo(urls)
                Waf(urls)
            else:
                urls = url.replace('\n','')
                InfoScan(urls)
                Cunhuo(urls)
                Waf(urls)
                JsFinder2(urls)
            # url = url.replace('\n', '')
            # InfoScan(url)  # result/get_domain_root(url).txt
            # Cunhuo(url)  # result/get_domain_root(url)_Cunhuo_url.txt
        End_cunhuo(file)
        try:
            End_waf(file)
        except Exception as e:
            print(e)
        End(file)       #将所有的子域名结果保存到result.txt中
    db.close()
        # JsFinder(url)       # result/get_domain_root(url)_link.txt      result/get_domain_root(url)_sub.txt
