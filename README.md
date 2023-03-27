# HexDnsEchoT

---

该工具由[https://github.com/sv3nbeast/DnslogCmdEcho](https://github.com/sv3nbeast/DnslogCmdEcho)修改而来。

## 背景

在一次日常渗透过程中，发现了一台机器可以利用jndi命令执行，但是无法注入内存马，也无法直接上线，所以想到了[https://github.com/sv3nbeast/DnslogCmdEcho](https://github.com/sv3nbeast/DnslogCmdEcho)这一工具来获取一些机器的信息，但是在使用过程中，发现该工具使用的DNS为dig.pm，但是dig.pm经过一些修改后变得时好时坏，无法接收到目标机器的请求，而且使用该工具需要执行两个python文件，非常的难受，因此产生了修改该工具的想法。

## 修改内容

* 将dig.pm修改为ceye.io，增加接收范围
* 添加自定义参数，不再需要在文件中修改
* 合并HexDnsEcho与CommandGen两个文件，使用更加方便
* 添加获取上一次命令执行结果的功能
* 兼容zsh
* 添加自定义dns服务器
* 实现有参数的命令执行，例如`ls -al`、`type file`、`cat file`等，由此可实现通过DNS读取文件

### 2023-03-27 来自r0fus0d(@No-Github)师傅的更新-[支持http basic认证的自建dig.pm](https://github.com/A0WaQ4/HexDnsEchoT/pull/4)

用于存在http basic认证的自建dig.pm

```bash
python3 HexDnsEchoT.py -ds DNS服务器 -tz 服务器时区 -cc dnsurl中点的数量+2 -u http_basic认证用户 -p http_basic认证密码
```

![](https://user-images.githubusercontent.com/18167071/227868628-58e221da-3620-431b-9552-49628c699fbd.png)

## 使用

```bash
usage: HexDnsEchoT.py [-h] [-d DNSURL] [-t TOKEN] [-lt LASTFINISHTIME]
                      [-f FILTER] [-ds DOMAIN_SERVER] [-tz TIMEZONE]
                      [-cc COUNT] [-m MODEL] [-u HTTPBASICUSER]
                      [-p HTTPBASICPASS]

options:
  -h, --help            show this help message and exit
  -d DNSURL, --dnsurl DNSURL
                        Ceye Dnslog
  -t TOKEN, --token TOKEN
                        Dns Server Token or CeyeToken
  -lt LASTFINISHTIME, --lastfinishtime LASTFINISHTIME
                        The LastFinishTime
  -f FILTER, --filter FILTER
                        Dns Filter
  -ds DOMAIN_SERVER, --domain_server DOMAIN_SERVER
                        Domain Server
  -tz TIMEZONE, --timezone TIMEZONE
                        Timezone
  -cc COUNT, --count COUNT
                        Count Counts
  -m MODEL, --model MODEL
                        Recent Result
  -u HTTPBASICUSER, --httpbasicuser HTTPBASICUSER
                        HTTPBasicAuth User
  -p HTTPBASICPASS, --httpbasicpass HTTPBASICPASS
                        HTTPBasicAuth Pass
```

因为ceye仅能保存100个数据，且会出现重复的情况下，添加自定义dns服务器

### Ceye

```bash
 python3 HexDnsEchoT.py -d YourCeye.ceye.io -t ceyeToken
```

![image-20230319185120315](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230319185120315.png)

![image-20230319185219861](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230319185219861.png)

### 自定义DNS服务器

```bash
python3 HexDnsEchoT.py -ds DNS服务器 -tz 服务器时区 -cc dnsurl中点的数量+2
```

例

```bash
python3 HexDnsEchoT.py -ds http://dig.pm -tz "UTC" -cc 7
```

服务器时区可以使用项目中的`Timezone.py`自行比对

![image-20230320160202914](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320160202914.png)

其中`-cc 7`为下图所示，dnsurl中5个点加2，为7

![image-20230320152449892](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320152449892.png)

可能等待结果返回的时间会比较长，请耐心等待

![image-20230320152816358](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320152816358.png)

注意：dig.pm有可能获取结果不稳定，大家可以自己搭建或者寻找其他DNSLOG平台使用，只需要满足为以下项目搭建即可：

[https://github.com/yumusb/DNSLog-Platform-Golang](https://github.com/yumusb/DNSLog-Platform-Golang)

或者是以`http://x.x.x.x/new_gen`获取随机子域名并以`http://x.x.x.x/token`获取dns结果的dnslog平台也可以使用

fofa可以直接搜索`DNSLOG Platform`寻找DNSLOG平台

![image-20230320154414350](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320154414350.png)

复制输出的命令，在目标机器上执行

![image-20230318021456697](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230318021456697.png)

DNS获取到请求，进行解密，获取机器信息

![image-20230318021542090](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230318021542090.png)

在linux上也可以执行获取结果

![image-20230318021732464](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230318021732464.png)

执行成功后自动开启新的filter，无需重新执行直接进行下一步命令执行

![image-20230319185425908](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230319185425908.png)

有时会出现目标机器的命令未执行完成，但是已经获取到了一部分结果，可以使用以下命令再次获取结果，本命令已经输出在上次的执行结果中，可直接复制使用

### Ceye

```shell
python3 HexDnsEchoT.py -d yourceye.ceye.io -t ceyetoken -f filterstr -lt "上次命令执行的时间" -m GR
```

![image-20230319185814165](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230319185814165.png)

![image-20230319185941334](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230319185941334.png)

### 自定义DNS服务器

```bash
python3 HexDnsEchoT.py -ds 自定义DNS服务器 -t 上一次执行的token -lt "上次命令执行的时间" -m GR -cc dnsurl中点的数量
```

以dig.pm为例

```bash
python3 HexDnsEchoT.py -ds http://dig.pm -t 上一次执行的token -lt "上次命令执行的时间" -m GR -cc 7
```

![image-20230320155144665](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320155144665.png)

可能等的时间会比较长，请耐心等待

![image-20230320154805306](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320154805306.png)

有参数的命令执行

```
ls -al
```

![image-20230320190108229](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320190108229.png)

```
type useruid.ini
```

![image-20230320190148588](https://github.com/A0WaQ4/HexDnsEchoT/blob/main/img/image-20230320190148588.png)



## 总结

在遇到工具无法使用的时候不要放弃，多想想办法就可以解决
