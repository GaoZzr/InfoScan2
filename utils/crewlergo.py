#!/usr/bin/python3
# coding: utf-8
import simplejson
import threading
import subprocess
import requests
import warnings
warnings.filterwarnings(action='ignore')


def opt2File(paths):
	try:
		f = open('crawl_result.txt','a')
		f.write(paths + '\n')
	finally:
		f.close()

def opt2File2(subdomains):
	try:
		f = open('sub_domains.txt','a')
		f.write(subdomains + '\n')
	finally:
		f.close()



def main(data1):
	target = data1
	cmd = ["crawlergo.exe", "-c", "C:\\Users\\华硕\\AppData\\Local\\Google\\Chrome SxS\\Application\\chrome.exe","-t", "1","-f","smart","--fuzz-path", "--push-to-proxy", "http://127.0.0.1:7777/", "--push-pool-max", "3","--output-mode", "json" , target]
	rsp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output, error = rsp.communicate()
	try:
		result = simplejson.loads(output.decode().split("--[Mission Complete]--")[1])
	except:
		return
	sub_domain = result["sub_domain_list"]
	print(data1)
	print("[crawl ok]")
	for subd in sub_domain:
		opt2File2(subd)
	for url in result[req_list]:
		opt2File(url)
	print("[scanning]")



if __name__ == '__main__':
	file = open("targets.txt")
	for text in file.readlines():
		data1 = text.strip('\n')
		main(data1)