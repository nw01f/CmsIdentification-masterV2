[原版来自世界上最大同性交友网站-传送门](https://github.com/theLSA/cmsIdentification)

##### 写在前面

针对原版进行修改，删除其他扫描选项，只采用结合式的扫描方法[关键字+MD5]。

新增`http://whatweb.bugscaner.com/look/`扫描接口，每天只能扫100个，网站上是怎么说的。应该勉强够用了。

新增支持批量url识别，需要一个url列表文件。

扫描方式，（1）先用本地指纹进行扫描，无结果，调用网络接口扫描。（2）设置参数直接使用whatweb网络接口扫描。

##### 写在中间

介绍一下参数的设置

    -f 文件名    # 设置url类表文件 PS:这个参数未测试。

    -u url       # 设置需要被识别的url

    -t 线程数    # 设置线程的数量，默认100

    -w           # 设置后，直接使用whatweb接口跳过本地检测，默认为否。

    -i           # 设置后，表示内网环境，将不再使用whatweb测试

##### 写在后面

简单介绍一下代码，方便阅读。

导入库

```python
import os
import json
import time
import thread
import gevent
import hashlib
import argparse
import requests

from colorama import init,Fore
from gevent.queue import Queue
from gevent import monkey;monkey.patch_all()
```

`gevent` 协程并发网络库

`argparse` 命令行参数解析库 

`colorama` 跨平台输出变色库

程序入口

```python
if __name__ == "__main__":
    init(autoreset=True)
    arg = Args()
    Cms = CmsInfo(arg.url,arg.is_internet,arg.thread,arg.whatweb,file=arg.file)
    Cms.RunIt()
```

调用参数解析函数，获得命令行参数，初始化CMS识别类，传入输入参数。调用`Runit`方法，开始扫描。

命令行参数解析，使用`argparse`库解析命令行参数。

```python
parse = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,add_help=False,description='''
    *===================================*
    |    Please set the parameters!     |
    |    Author:nw01f                   |
    |    Version:1.0                    |
    |    Time:2018/12/25                |
    *===================================*
    ''')
    parse.add_argument('-f','--file',help='Please set FILE')
    parse.add_argument('-u','--url',help="Please set scan URL")
    parse.add_argument('-t','--thread',default=100,help='Please set Thread Number',type=int)
    parse.add_argument('-w','--whatweb',default=False,help='Use whatweb probe directly',action="store_true")   # 设置后跳过本地指纹检测,直接使用whatweb接口探测,默认为否
    parse.add_argument('-i','--is_internet',help="network environments,default true;if it's set,it will not be tested online",default=True,action="store_false")           # 是否可以访问互联网，默认可以，设置后表示不可以
    args = parse.parse_args()
    if args.url is None and args.file is None :
        print parse.print_help()
        exit()
    else :
        return args
```

解析命令行参数，设置默认值。

类函数`Runit()`

```python
def RunIt(self):
    print Fore.CYAN + '[Message]:The program starts running...' #程序开始运行
    self.UrlMake2Queue()
    while not self.UrlQueue.empty() :
        ## 在队列为空前 发现cms类型,下个URL开始前,应将指纹队列先清空
        self.CmsMake2Queue()
        url = self.UrlQueue.get()
        if not self.whatweb :
            corlist = [gevent.spawn(self.Get2Location,url) for i in range(self.thread)]
            gevent.joinall(corlist)
            if self.res.empty() and self.IsInternet :
                print Fore.CYAN + '[Message]: The local fingerprint is not found, and the network interface is called.' # 本地指纹未发现,调用网络接口
                self.Get2Internet(url)
        else:
            self.Get2Internet(url)
    print Fore.CYAN + '[Message]: Log generation.'  # 日志生成中
    self.ErrorLog()
    self.ResultLog()
    print Fore.CYAN + '[Message]:The program end.'
    exit()
```

使用`self.UrlMake2Queue()`对传入的url或者url列表文件进行处理，打包成队列。

```python
def UrlMake2Queue(self):
    if self.desurl is not None:
        self.UrlQueue.put(self.desurl.strip('/'))
        return True
    if self.file is not None:
        if not os.path.exists(arg.file):
            print Fore.RED + '[Error]:File not found'   #文件不存在
        else :
            try:
                target = open(arg.file,'r')
                lines = target.readlines()
                for line in lines:
                    self.UrlQueue.put(line.strip().strip('/'))
                target.close()
                return True
            except BaseException as e :
                print Fore.RED + '[Error]:File %s open filed\n%s' %(arg.file, e)   # 文件打开失败
                exit()

```

使用`self.CmsMake2Queue()`将本地CMS指纹`data.json`打包成队列。

```python
def CmsMake2Queue(self):
    fp = open('data.json','r')
    CmsData = json.load(fp,encoding="utf-8")
    for i in CmsData :
        self.location.put(i)
    fp.close()
```

使用`corlist = [gevent.spawn(self.Get2Location,url) for i in range(self.thread)]`协程网络并发库进行多线程扫描。

使用`self.Get2Location(url)`进行本地指纹识别。

```python
def Get2Location(self,url):
    while not self.location.empty():
        CmsJson = self.location.get()
        FinalUrl = url + CmsJson['url']
        print Fore.CYAN + '[Message]: %s' % FinalUrl
        RspHtmlC = ''
        try:
            rsp = requests.get(FinalUrl,headers=self.header2,timeout=3)
            if rsp.status_code != 200 :
                continue
            RspHtmlC = rsp.content
            if RspHtmlC is None :
                continue
        except BaseException as e :
            RspHtmlC = ''
            self.message.put({'error':'Network anomalies or Program error. On: Get2Location. URL:%s\n%s' %(url,e)}) # 网络异常或者程序出错,抛出异常,目的域名
            continue
        if CmsJson['re'] :
            if RspHtmlC.find(CmsJson['re']) != -1 :
                self.res.put({'LocResult':'Target cms is : %s Source : %s KeyWord : %s' %(CmsJson['name'],url,CmsJson['re'])})
                print Fore.GREEN + '[LocResult]: Target cms is : %s Source : %s KeyWord : %s' %(CmsJson['name'],url,CmsJson['re'])
                self.CleaerQueue()
                return True
        else:
            md5 = self.GetMd5(RspHtmlC)
            if md5 == CmsJson['md5'] :
                self.res.put({'LocResult':'Target cms is : %s Source : %s KeyWord : %s' %(CmsJson['name'],url,CmsJson['md5'])})
                print Fore.GREEN + '[LocResult]: Target cms is : %s Source : %s KeyWord : %s' %(CmsJson['name'],url,CmsJson['md5'])
                self.CleaerQueue()
                return True
```

使用`self.GetMd5()`对返回结果进行MD5编码

```python
def GetMd5(self,repfile):
    md5 = hashlib.md5()
    md5.update(repfile)
    return md5.hexdigest()
```

发现可匹配的指纹后，使用`def CleaerQueue()`清空指纹队列。

```python
def CleaerQueue(self):
    while not self.location.empty() :
        self.location.get()
```

使用`self.Get2Internet(url)`调用whatweb接口进行指纹识别。

```python
def Get2Internet(self,url):
    if self.IsInternet :
        whatweb = 'http://whatweb.bugscaner.com/what/'
        data = {'url':url}
        if self.flag :
            try:
                response = requests.post(whatweb,headers=self.header1,timeout=self.timeout,data=data).text
                info = json.loads(response)
                if info['error'] == 'no' :
                    # 结果返回正常
                    s = ''
                    s = 'Cms: [' + info['CMS'] + '] Other: {'
                    for k,v in info.items() :
                        if k != 'url' and k != 'error' and k != 'CMS':
                            for target_list in v :
                                s = s + k + ': [' +target_list + '] '
                    s = s + '} Url: [' + info['url'] + ']'
                    self.res.put({'InterResult':info})
                    print Fore.GREEN + '[InterResult]: ' + s
                    return True
                    # 结果返回犯错 对返回的错误进行处理
                if info['error'] == '1' :
                    self.message.put({'error':'Domain cannot be accessed. Url: %s' %(url)})  # 域名不能访问
                    print Fore.RED + '[Error]: Domain cannot be accessed. Url: %s' %(url)
                    return False
                if info['error'] == '2' :
                    self.message.put({'info' :'More than 100 queries. Url: %s' %(url) })  # 查询次数超过100次
                    print Fore.YELLOW + '[Info]: More than 100 queries. Url: %s' %(url)
                    self.flag = False
                    return False
                if info['error'] == '3' :
                    self.message.put({'unres':'Not recognized.Url: %s' %(url)}) # 无法识别
                    print Fore.BLUE + '[Unres]: Not recognized.Url: %s' %(url)
                    return False
                if info['error'] == '4' :
                    self.message.put({'error':'Server debugging. Url: %s' %(url)}) # 服务器调试
                    print Fore.RED + '[Error]: Server debugging. Url: %s' %(url)
                    return False
                if info['error'] == '5' :
                    self.message.put({'error':'Access too fast. Url: %s' %(url)}) # 访问速度太快
                    print Fore.RED + '[Error]: Access too fast. Url: %s' %(url)
                    return False
            except BaseException as e:
                self.message.put({'error':'Network anomalies or Program error On: Get2Internet Destination URL:%s\n%s' %(url,e)})  # 网络异常或者程序出错,抛出异常,目的域名
                print Fore.RED + '[Error]: Network anomalies or Program error On: Get2Internet Destination URL:%s\n%s' %(url,e)
                return False
        else:
            self.message.put({'info' :'More than 100 queries Url: %s' %(url) })  # 查询次数超过100次
            print Fore.YELLOW + '[Info]: More than 100 queries Url: %s' %(url)
            return False
    else:
        print '[Message]: Set the -i parameter'
        return False
```

##### 写在最后

使用方法

```bash
python CmsIdentificationV2.py -u http://127.0.0.1
# 使用默认值扫描，当本地指纹无法识别时，会调用whatweb进行识别
python CmsIdentificationV2.py -u http://127.0.0.1 -t 200
# 将线程数量修改为200
python CmsIdentificationV2.py -u http://127.0.0.1 -t 200 -i
# 只使用本地指纹扫描
python CmsIdentificationV2.py -u http://127.0.0.1 -t 200 -w
# 跳过本地检测，直接使用whatweb接口识别
python CmsIdentificationV2.py -f url.txt
# 对url列表进行识别
```