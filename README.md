# nmap-x
 rustscan+nmap结合工具
# 说明

​	本工具是为了补充rustscan扫描出结果没有详细端口指纹信息的问题，采取nmap对指定端口进行扫描，输出结果。

# 使用说明

```
nmapx -input {{portrawfile}} -output {{Output}}/portscan/nmap
```

​	默认安装了rustscan！结果将会保存到上面指定的路径，输出文件格式为ip.xml
