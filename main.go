package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

var (
	inputFilePath    = flag.String("input", "", "Path to the input file")
	outputFolderPath = flag.String("output", "", "Path to the output folder")
)

// parseFile 函数应该返回一个映射，其中键是 IP 地址，值是端口列表
// isInternalIP 判断 IP 是否为内网 IP
func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true // 127.0.0.1 是内网 IP
	}
	privateBlocks := []*net.IPNet{
		mustParseCIDR("10.0.0.0/8"),
		mustParseCIDR("172.16.0.0/12"),
		mustParseCIDR("192.168.0.0/16"),
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// mustParseCIDR 解析 CIDR 字符串并返回 *net.IPNet
// 如果解析失败，则 panic
func mustParseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic("Invalid CIDR: " + s)
	}
	return net
}

func main() {

	flag.Parse()

	if *inputFilePath == "" || *outputFolderPath == "" {
		log.Fatal("Both input and output file paths are required")
	}

	// 创建输出文件夹，如果不存在
	err := os.MkdirAll(*outputFolderPath, 0755)
	if err != nil {
		log.Fatalf("Failed to create output folder: %s", err)
	}

	// 读取并解析文件内容
	ipPortMap := parseFile(*inputFilePath)

	// 遍历 IP 和端口列表，执行 nmap 扫描并将结果保存到对应 IP 地址的 xml 文件中
	for ip, ports := range ipPortMap {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			log.Printf("Invalid IP address: %s, skipping", ip)
			continue
		}
		if isInternalIP(parsedIP) {
			fmt.Printf("Skipping internal IP: %s\n", ip)
			continue
		}
		fmt.Println(ip)
		port := strings.Join(ports, ",")
		if len(ports) > 1000 {
			fmt.Printf("Ports length %d > 1000, skipping... \n", len(ports))
			continue
		}
		fmt.Println(port)
		outputFilePath := fmt.Sprintf("%s/%s.xml", *outputFolderPath, ip)
		fmt.Printf("输出文件 outputFilePath: %s", outputFilePath)
		cmd := exec.Command("nmap", "-sV", "-sS", "-p", port, "-oX", outputFilePath, ip)
		err := cmd.Run()
		if err != nil {
			log.Fatalf("Error running nmap for %s:%s: %s", ip, port, err)
		}
	}
	fmt.Println("Scanning completed. Results appended to the output folder.")
}

// parseFile 解析输入文件，返回 IP 地址和端口列表的映射
func parseFile(filePath string) map[string][]string {
	ipPortMap := make(map[string][]string)

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Error opening file %s: %s", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, " -> ")
		if len(fields) != 2 {
			log.Fatalf("Invalid line format: %s", line)
		}

		ip := strings.TrimSpace(fields[0])
		portsStr := strings.Trim(fields[1], "[]")
		ports := strings.Split(portsStr, ",")

		var portList []string
		for _, portStr := range ports {
			if err != nil {
				log.Fatalf("Invalid port number: %s", portStr)
			}
			portList = append(portList, portStr)
		}

		ipPortMap[ip] = portList
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file %s: %s", filePath, err)
	}

	return ipPortMap
}
