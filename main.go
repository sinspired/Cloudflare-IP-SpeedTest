package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-ieproxy"
	"golang.org/x/sys/windows/registry"
)

var (
	requestURL       = "speed.cloudflare.com/cdn-cgi/trace"     // 请求trace URL
	locationsJsonUrl = "https://speed.cloudflare.com/locations" //location.json下载 URL
)

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
)

var (
	File         = flag.String("file", "ip.txt", "IP地址文件名称")                                   // IP地址文件名称
	outFile      = flag.String("outfile", "ip.csv", "输出结果文件名称")                                // 输出结果文件名称
	defaultPort  = flag.Int("port", 443, "端口")                                                 // 端口
	maxThreads   = flag.Int("max", 100, "并发请求最大线程数")                                           // 最大线程数
	speedTest    = flag.Int("speedtest", 5, "下载测速线程数量,设为0禁用测速")                                // 下载测速线程数量
	speedLimit   = flag.Int("speedlimit", 2, "最低下载速度，默认2MB/s")                                 // 最低下载速度
	speedTestURL = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	enableTLS    = flag.Bool("tls", true, "是否启用TLS")                                           // TLS是否启用
	multipleNum  = flag.Float64("mulnum", 1, "多线程测速造成测速不准，可进行倍数补偿")                            //speedTest比较大时修改
	tcpLimit     = flag.Int("tcplimit", 1000, "TCP最大延迟，默认1000 ms")                             // 最低下载速度
)

type result struct {
	ip          string        // IP地址
	port        int           // 端口
	dataCenter  string        // 数据中心
	region      string        // 地区
	domainAbbr  string        // 顶级域名后缀
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

type speedtestresult struct {
	result
	downloadSpeed float64 // 下载速度
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// 尝试提升文件描述符的上限
func increaseMaxOpenFiles() {
	fmt.Println("正在尝试提升文件描述符的上限...")
	cmd := exec.Command("bash", "-c", "ulimit -n 10000")
	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
	} else {
		fmt.Printf("文件描述符上限已提升!\n")
	}
}

// downloadWithIEProxy 尝试使用IE代理设置下载文件
func downloadWithIEProxy(downloadURL string) ([]byte, error) {
	proxyFunc := ieproxy.GetProxyFunc()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: proxyFunc},
	}

	resp, err := client.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("下载时出错: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body) // 尝试读取响应体以获取更多错误信息
		return nil, fmt.Errorf("非预期的HTTP状态码: %v, 响应体: %s", resp.Status, string(body))
	}

	return ioutil.ReadAll(resp.Body)
}

// 定义外网域名google.com检测函数
func checkProxyEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		fmt.Println("无法打开注册表键:", err)
		return false
	}
	defer k.Close()

	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil {
		fmt.Println("无法读取ProxyEnable值:", err)
		return false
	}

	return proxyEnable == 1 //proxyEnable键值若为1，说明开启了代理服务器，返回true
}

// checkNormalUrl 尝试连接指定的URL，检查网站是否可访问
func checkNormalUrl(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		//fmt.Printf("访问 %s 时未知错误:[ %v ]\n", url, err)
		return false
	}
	defer resp.Body.Close()
	//fmt.Println("检测可以ping通:" + url)
	return true
}

// 根据域名检测连通性，自动检测代理服务器.
func checkProxyUrl(urlStr string) bool {
	proxyFunc := ieproxy.GetProxyFunc()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: proxyFunc},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		//fmt.Printf("Error accessing %s: %v\n", urlStr, err)
		return false
	}
	defer resp.Body.Close()

	//fmt.Println("成功连接: " + urlStr)
	return true
}

func main() {
	flag.Parse()

	startTime := time.Now()
	osType := runtime.GOOS
	if osType == "linux" {
		increaseMaxOpenFiles()
	}

	/*	//检查默认cloudflare官方测速地址连通性
		if checkNormalUrl("https://" + requestURL) {
			fmt.Println(requestURL + "：状态正常") //debug info
		} else if checkNormalUrl("https://" + "speed.bestip.one/locations") {
			// Cloudflare不可访问，使用Bestip
			fmt.Println("无法访问speed.cloudflare.com，更换节点。")
			requestURL = strings.Replace(requestURL, "speed.cloudflare.com", "speed.bestip.one", 1)
			*speedTestURL = strings.Replace(*speedTestURL, "speed.cloudflare.com", "speed.bestip.one", 1)
			locationsJsonUrl = strings.Replace(locationsJsonUrl, "speed.cloudflare.com", "speed.bestip.one", 1)
		} else {
			//requestURL = strings.Replace(requestURL, "speed.cloudflare.com", "speed.bestip.one", 1)
			fmt.Println("无法下载locations.json，尝试添加系统代理下载。")
		}*/

	// 检查location.json文件，如不存在，则从网络下载
	var locations []location //创建location数组以存储json文件，
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("正在从 " + locationsJsonUrl + " 下载 locations.json")

		body, err := downloadWithIEProxy(locationsJsonUrl)
		if err != nil {
			fmt.Printf("下载失败: %v\n", err)
			return
		}
		// 检查下载的数据
		fmt.Printf("下载的数据长度: %d\n", len(body))
		//fmt.Printf("下载的数据内容: %s\n", string(body))

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		file, err := os.Create("locations.json")
		if err != nil {
			fmt.Printf("无法创建文件: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			fmt.Printf("无法写入文件: %v\n", err)
			return
		}
	} else {
		fmt.Println("\033[0;90m本地 locations.json 已存在,无需重新下载\033[0m")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer file.Close()

		body, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Printf("无法读取文件: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
	}

	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	// 检查系统代理是否启用
	if checkProxyEnabled() {
		fmt.Println("\033[2J\033[0;0H\033[31m检测到系统代理已启用，请关闭VPN后重试。\033[0m")
		return
	} else {
		fmt.Println("\033[90m系统代理未启用，检测tun模式代理……\033[0m")
	}

	// 检查Google.com是否可访问
	if checkProxyUrl("https://www.google.com") {
		fmt.Println("\033[31m已开启tun模式代理，可以访问外网，请关闭VPN后重试。\033[0m")
	} else {
		fmt.Println("\033[90m未开启vpn，检测墙内网络是否正常……\033[0m")
	}
	// 检测Baidu是否可访问
	if !checkNormalUrl("https://www.baidu.com") {
		fmt.Println("\033[2J\033[0;0H\033[31m无互联网访问，请检查网络连接。\033[0m")
		return
	} else {
		// 清除输出内容
		fmt.Print("\033[2J\033[0;0H")
		fmt.Println("\033[32m网络环境正常，读取ip列表进行tcp延迟检测……\033[0m")
	}

	// 如果Google不可访问，Baidu可以访问，说明网络环境正常。开始读取ip列表进行tcp延迟检测
	ips, err := readIPs(*File)
	if err != nil {
		fmt.Printf("\033[31m无法从文件中读取 IP: %v\033[0m\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(ips))

	resultChan := make(chan result, len(ips))

	thread := make(chan struct{}, *maxThreads)

	var countAll int   //TCP延迟检测计数器
	var countAlive int //有效IP计数器
	total := len(ips)

	for _, ip := range ips {

		countAll++
		percentage := float64(countAll) / float64(total) * 100
		fmt.Printf("已检测: %d 总数: %d 进度: %.2f%%  存活ip:  \033[1;32m\033[5m%d\033[0m\r", countAll, total, percentage, countAlive)

		if countAll == total {
			fmt.Printf("\n")
			//fmt.Printf("\n已完成: %d 发现有效ip: %d ---任务进度：[ %.0f%% ]\n", countAll, countAlive,percentage)
		}

		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()

				/* //计数器和输出代码在这个位置会导致输出错误
				countAll++
				percentage := float64(countAll) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", countAll, total, percentage)
				if countAll == total {
					fmt.Printf("已完成: %d 发现有效ip: %d 个\n", countAll, countAlive)
				} */
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: timeout,
			}

			var protocol string
			if *enableTLS {
				protocol = "https://"
			} else {
				protocol = "http://"
			}
			requestURL := protocol + requestURL

			req, _ := http.NewRequest("GET", requestURL, nil)

			// 添加用户代理
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			duration := time.Since(start)
			if duration > maxDuration {
				return
			}

			buf := &bytes.Buffer{}
			// 创建一个读取操作的超时
			timeout := time.After(maxDuration)
			// 使用一个 goroutine 来读取响应体
			done := make(chan bool)
			go func() {
				_, err := io.Copy(buf, resp.Body)
				done <- true
				if err != nil {
					return
				}
			}()
			// 等待读取操作完成或者超时
			select {
			case <-done:
				// 读取操作完成

			case <-timeout:
				// 读取操作超时
				return
			}

			body := buf
			if err != nil {
				// 处理错误，例如日志记录
				fmt.Printf("Error occurred: %v", err)
				return
			}

			if strings.Contains(body.String(), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if float64(tcpDuration.Milliseconds()) <= float64(*tcpLimit) {
						if ok {
							fmt.Printf("发现有效IP %s 位置: %s.%s 延迟 %d 毫秒\n", ip, loc.City, loc.Cca2, tcpDuration.Milliseconds())
							resultChan <- result{ip, *defaultPort, dataCenter, loc.Region, loc.Cca2, loc.City, fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration} //删掉excel中的 ms单位。tcpDuration变量
						} else {
							fmt.Printf("发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ip, tcpDuration.Milliseconds())
							resultChan <- result{ip, *defaultPort, dataCenter, "", "", "", fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration} //删掉excel中的 ms单位。tcpDuration变量
						}
						countAlive++
					}

				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	if len(resultChan) == 0 {
		// 清除输出内容
		//fmt.Print("\033[2J")
		fmt.Println("\033[31m没有发现有效的IP\033[0m")
		return
	}

	var countSt int
	var results []speedtestresult
	if *speedTest > 0 {
		fmt.Printf("\n开始下载测速\n")
		var wg2 sync.WaitGroup
		wg2.Add(*speedTest)
		countSt = 0 //下载测速进度计数器
		total := len(resultChan)
		results = []speedtestresult{}
		for i := 0; i < *speedTest; i++ {
			thread <- struct{}{}
			go func() {
				defer func() {
					<-thread
					wg2.Done()
				}()
				for res := range resultChan {

					countSt++ //记录下载测速进度
					percentage := float64(countSt) / float64(total) * 100
					//fmt.Printf("已完成: %.2f%%\r", percentage)

					downloadSpeed := getDownloadSpeed(res.ip)
					results = append(results, speedtestresult{result: res, downloadSpeed: downloadSpeed})
					if percentage == 100 {
						// 清除输出内容
						//fmt.Print("\033[2J")
						fmt.Printf("下载测速进度 \033[1;32m%.2f%%\033[0m\n", percentage)

					}

				}
			}()
		}
		wg2.Wait()

	} else {
		for res := range resultChan {
			results = append(results, speedtestresult{result: res})
		}
	}

	if *speedTest > 0 {
		sort.Slice(results, func(i, j int) bool {
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
	} else {
		sort.Slice(results, func(i, j int) bool {
			return results[i].result.tcpDuration < results[j].result.tcpDuration
		})
	}

	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()

	// 标记为utf-8 bom编码,防止excel打开中文乱码
	file.WriteString("\xEF\xBB\xBF")

	file2, err := os.Create("lowspeedList.csv")
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file2.Close()

	// 标记为utf-8 bom编码,防止excel打开中文乱码
	file2.WriteString("\xEF\xBB\xBF")
	writer2 := csv.NewWriter(file2)

	writer := csv.NewWriter(file)
	if *speedTest > 0 {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)", "下载速度(MB/s)"})
		writer2.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)", "下载速度(MB/s)"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)"})
		writer2.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)"})
	}

	fmt.Printf("\n优选测速结果：\n")
	for _, res := range results {
		if *speedTest > 0 {
			if res.downloadSpeed >= float64(*speedLimit) {
				writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})
				fmt.Printf("IP %s 下载速度 %.1f MB/s,高于 %d MB/s，已写入 %s!\n", res.result.ip, res.downloadSpeed, *speedLimit, *outFile)
			} else {
				writer2.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})

				fmt.Printf("IP %s 下载速度 %.1f MB/s,低于 %d MB/s，已写入 lowspeedList.csv\n", res.result.ip, res.downloadSpeed, *speedLimit)
			}
		} else {
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency})
			writer2.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency})

		}
	}

	writer.Flush()
	writer2.Flush()
	// 清除输出内容
	//fmt.Print("\033[2J")
	fmt.Printf("\n高速ip写入 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
	fmt.Printf("低速ip写入 lowspeedList.csv，耗时 %d秒\n", time.Since(startTime)/time.Second)
}

// 从文件中读取IP地址
func readIPs(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 创建一个 map 存储不重复的 IP 地址
	ipMap := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddr := scanner.Text()
		// 判断是否为 CIDR 格式的 IP 地址
		if strings.Contains(ipAddr, "/") {
			ip, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				fmt.Printf("无法解析CIDR格式的IP: %v\n", err)
				continue
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
				ipMap[ip.String()] = struct{}{}
			}
		} else {
			ipMap[ipAddr] = struct{}{}
		}
	}

	// 将 map 的键转换回切片，获得去重的ip地址
	ips := make([]string, 0, len(ipMap))
	for ip := range ipMap {
		ips = append(ips, ip)
	}

	fmt.Println("\n成功获取去重ip列表，开始TCP延迟检测...")

	return ips, scanner.Err()
}

// inc函数实现ip地址自增
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 测速函数
func getDownloadSpeed(ip string) float64 {
	var protocol string
	if *enableTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	speedTestURL := protocol + *speedTestURL
	// 创建请求
	req, _ := http.NewRequest("GET", speedTestURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	// 创建TCP连接
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 0,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
	if err != nil {
		return 0
	}
	defer conn.Close()

	fmt.Printf("正在测试IP %s 端口 %s\r", ip, strconv.Itoa(*defaultPort))
	startTime := time.Now()
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		//设置单个IP测速最长时间为5秒
		Timeout: 5 * time.Second,
	}
	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("IP %s 端口 %s 测速无效\n", ip, strconv.Itoa(*defaultPort))
		return 0
	}
	defer resp.Body.Close()

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)

	speed_orignal := float64(written) / duration.Seconds() / (1024 * 1024) //真实测速数据，如开多线程会有失真。单位MB/s
	//speed_KB := float64(written) / duration.Seconds() / 1024  //单位KB/s

	if *multipleNum > 1 && *speedTest >= 5 {
		//多线程测速会有速度损失，加以补偿
		speed := float64(written) / duration.Seconds() / (1024 * 1024) * (*multipleNum)
		fmt.Printf("IP %s 端口 %s 下载速度 %.1f MB/s, 补偿系数 %.0f, 原速度 %.1f MB/s\n", ip, strconv.Itoa(*defaultPort), speed, *multipleNum, speed_orignal)
		return speed
	} else {
		speed := float64(written) / duration.Seconds() / (1024 * 1024)
		// 输出结果
		fmt.Printf("IP %s 端口 %s 下载速度 %.1f MB/s\n", ip, strconv.Itoa(*defaultPort), speed)
		return speed
	}

}
