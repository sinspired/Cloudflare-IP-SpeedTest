package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"ipspeedtest/task"
)

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
)

var (
	requestURL       = "speed.cloudflare.com/cdn-cgi/trace"     // 请求trace URL
	locationsJsonUrl = "https://speed.cloudflare.com/locations" // location.json下载 URL
)

var (
	File         = flag.String("file", "ip.txt", "IP地址文件名称(*.txt或*.zip)")                      // IP地址文件名称
	outFile      = flag.String("outfile", "result.csv", "输出文件名称(自动设置)")                        // 输出文件名称
	defaultPort  = flag.Int("port", 443, "端口")                                                 // 端口
	maxThreads   = flag.Int("max", 100, "并发请求最大协程数")                                           // 最大协程数
	speedTest    = flag.Int("speedtest", 5, "下载测速协程数量,设为0禁用测速")                                // 下载测速协程数量
	speedLimit   = flag.Int("speedlimit", 5, "最低下载速度(MB/s)")                                   // 最低下载速度
	speedTestURL = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	enableTLS    = flag.Bool("tls", true, "是否启用TLS")                                           // TLS是否启用
	multipleNum  = flag.Float64("mulnum", 1, "多协程测速造成测速不准，可进行倍数补偿")                            // speedTest比较大时修改
	tcpLimit     = flag.Int("tcplimit", 1000, "TCP最大延迟(ms)")                                   // TCP最大延迟(ms)
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
	var locations []location // 创建location数组以存储json文件，
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("正在从 " + locationsJsonUrl + " 下载 locations.json")

		body, err := downloadWithIEProxy(locationsJsonUrl)
		if err != nil {
			fmt.Printf("下载失败: %v\n", err)
			return
		}

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
		fmt.Println("\033[32m成功下载并创建 location.json\033[0m")
	} else {
		fmt.Println("\033[0;90m本地 locations.json 已存在,无需重新下载\033[0m")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer file.Close()

		body, err := io.ReadAll(file)
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

	// 网络环境检测，如网络不正常自动退出
	autoNetworkDetection()

	// 调用 autoSetFileName 函数，自动设置输入文件格式
	autoSetFileName("ip.txt", "ip.zip")

	// 重定义输出文件名
	outFileUnqualified := "result_Unqualified.csv"
	if strings.Contains(*File, "_") {
		FileName := strings.Split(*File, ".")[0]      // 去掉后缀名
		resultName := strings.Split(FileName, "_")[1] // 分离名字字段
		caser := cases.Title(language.English)        // 使用English作为默认语言标签
		resultName = caser.String(resultName)         // 首字母大写

		if *outFile == "result.csv" {
			*outFile = "result_" + resultName + ".csv"
		}
		outFileUnqualified = "result_" + resultName + "_Unqualified.csv"
	}

	// 根据指定IP文件路径读取ip列表
	ips, err := readIPs(*File)
	if err != nil {
		fmt.Printf("\033[31m无法从文件中读取 IP: %v\033[0m\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(ips))

	resultChan := make(chan result, len(ips))

	thread := make(chan struct{}, *maxThreads)

	total := len(ips)      // ip数据总数
	var countAll int       // TCP延迟检测计数器
	var countAlive int     // 有效IP计数器
	var percentage float64 // 检测进度百分比

	for _, ip := range ips {
		// 计数器
		countAll++
		percentage = float64(countAll) / float64(total) * 100

		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()

				// 并发检测进度显示
				fmt.Printf(":已检测: %d 总数: %d 进度: %.2f%%  存活ip:  \033[1;32m\033[5m%d\033[0m\r", countAll, total, percentage, countAlive)
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()

			// 使用新的DialContext函数,这里context.Background()提供了一个空的上下文
			// conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort))),已淘汰的Dial
			conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					// 使用新的DialContext函数
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
			body := buf // 将body声明移动到这里
			// 创建一个读取操作的超时
			timeout := time.After(maxDuration)
			// 使用一个 goroutine 来读取响应体
			done := make(chan bool)
			go func() {
				_, copyErr := io.Copy(buf, resp.Body)
				done <- true
				if copyErr != nil {
					// 在这里处理goroutine中的错误
					// fmt.Printf("读取响应体错误: %v", copyErr)
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

			if strings.Contains(body.String(), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if float64(tcpDuration.Milliseconds()) <= float64(*tcpLimit) {
						countAlive++ // 记录存活IP数量
						if ok {
							fmt.Printf("-发现有效IP %s 位置: %s.%s 延迟 %d 毫秒\n", ip, loc.City, loc.Cca2, tcpDuration.Milliseconds())
							resultChan <- result{ip, *defaultPort, dataCenter, loc.Region, loc.Cca2, loc.City, fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration} // 删掉excel中的 ms单位。tcpDuration变量
						} else {
							fmt.Printf("-发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ip, tcpDuration.Milliseconds())
							resultChan <- result{ip, *defaultPort, dataCenter, "", "", "", fmt.Sprintf("%d", tcpDuration.Milliseconds()), tcpDuration} // 删掉excel中的 ms单位。tcpDuration变量
						}
					}
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	// 并发检测执行完毕后输出信息
	if countAll == total {
		fmt.Printf(":已检测: %d 总数: %d 进度: \033[32m%.2f%%\033[0m  存活ip:  \033[1;32m\033[5m%d\033[0m\r", countAll, total, percentage, countAlive)
		fmt.Printf("\nTCP延迟检测完成！\n")
	}

	if len(resultChan) == 0 {
		// 清除输出内容
		// fmt.Print("\033[2J")
		fmt.Println("\033[31m没有发现有效的IP\033[0m")
		return
	}

	var countSt int
	var results []speedtestresult
	if *speedTest > 0 {
		fmt.Printf("\n开始下载测速\n")
		var wg2 sync.WaitGroup
		wg2.Add(*speedTest)
		countSt = 0 // 下载测速进度计数器
		total := len(resultChan)
		results = []speedtestresult{}
		for i := 0; i < *speedTest; i++ {
			thread <- struct{}{}
			go func() {
				defer func() {
					<-thread
					wg2.Done()
					// 输出下载测速进度
					percentage := float64(countSt) / float64(total) * 100
					if percentage == 100 {
						fmt.Printf("下载测速进度已完成 \033[1;32m%.2f%%\033[0m\r", percentage)
					}
				}()

				for res := range resultChan {
					countSt++ // 记录下载测速进度
					percentage := float64(countSt) / float64(total) * 100

					downloadSpeed := getDownloadSpeed(res.ip)
					results = append(results, speedtestresult{result: res, downloadSpeed: downloadSpeed})

					fmt.Printf("协程 \033[33m%d\033[0m 下载测速进度 \033[1;32m%.2f%%\033[0m\r", i, percentage)
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

	// 达标的测速ip输出到一个文件
	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()
	file.WriteString("\xEF\xBB\xBF") // 标记为utf-8 bom编码,防止excel打开中文乱码

	// 未达标的测速ip输出到一个文件
	fileUnqualified, err := os.Create(outFileUnqualified)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer fileUnqualified.Close()
	fileUnqualified.WriteString("\xEF\xBB\xBF") // 标记为utf-8 bom编码,防止excel打开中文乱码

	writer := csv.NewWriter(file)
	writerUnqualified := csv.NewWriter(fileUnqualified)

	if *speedTest > 0 {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)", "下载速度(MB/s)"})
		writerUnqualified.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)", "下载速度(MB/s)"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)"})
		writerUnqualified.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "域名后缀", "城市", "网络延迟(ms)"})
	}
	// fmt.Printf("\n")
	fmt.Printf("\n\n优选ip测速结果：\n")
	for _, res := range results {
		if *speedTest > 0 {
			if res.downloadSpeed >= float64(*speedLimit) {
				// 根据设定限速值，测速结果写入不同文件
				writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})
				fmt.Printf("IP %s 下载速度 %.1f MB/s,高于 %d MB/s，已写入 %s\n", res.result.ip, res.downloadSpeed, *speedLimit, *outFile)
			} else {
				writerUnqualified.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency, fmt.Sprintf("%.1f", res.downloadSpeed)})

				// fmt.Printf("IP %s 下载速度 %.1f MB/s,低于 %d MB/s，已写入 %s\n", res.result.ip, res.downloadSpeed, *speedLimit, outFileUnqualified)
			}
		} else {
			writer.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency})
			writerUnqualified.Write([]string{res.result.ip, strconv.Itoa(res.result.port), strconv.FormatBool(*enableTLS), res.result.dataCenter, res.result.region, res.result.domainAbbr, res.result.city, res.result.latency})

		}
	}

	writer.Flush()
	writerUnqualified.Flush()
	// 清除输出内容
	// fmt.Print("\033[2J")
	fmt.Printf("\n> 优质ip写入 \033[90m%s\033[0m 耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
	fmt.Printf("> 低速ip写入 \033[90m%s\033[0m 耗时 %d秒\n", outFileUnqualified, time.Since(startTime)/time.Second)
}

// autoNetworkDetection 自动检测网络环境，返回一个bool值
func autoNetworkDetection() bool {
	// 检查系统代理是否启用
	if checkProxyEnabled() {
		fmt.Println("\033[2J\033[0;0H\033[31m检测到系统代理已启用，请关闭VPN后重试。\033[0m")
		return false
	} else {
		fmt.Println("\033[90m系统代理未启用，检测tun模式代理……\033[0m")

		// 检查Google.com是否可访问
		if checkProxyUrl("https://www.google.com") {
			fmt.Println("\033[31m已开启tun模式代理，可以访问外网，请关闭VPN后重试。\033[0m")
			return false
		} else {
			fmt.Println("\033[90m未开启vpn，检测墙内网络是否正常……\033[0m")
		}
	}

	// 检测Baidu是否可访问
	if !checkNormalUrl("https://www.baidu.com") {
		fmt.Println("\033[2J\033[0;0H\033[31m无互联网访问，请检查网络连接。\033[0m")
		return false
	} else {
		// 清除输出内容
		fmt.Print("\033[2J\033[0;0H")
		fmt.Printf("\033[32m网络环境检测正常 \033[0m\n")
	}
	return true
}

// checkProxyEnabled 检测是否开启系统代理服务器
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

	return proxyEnable == 1 // proxyEnable键值若为1，说明开启了代理服务器，返回true
}

// checkNormalUrl 尝试连接指定的URL，检查网络是否可访问
func checkNormalUrl(url string) bool {
	resp, err := http.Get(url)
	if err != nil {
		// fmt.Printf("访问 %s 时未知错误:[ %v ]\n", url, err)
		return false
	}
	defer resp.Body.Close()
	// fmt.Println("检测可以ping通:" + url)
	return true
}

// checkProxyUrl 根据域名检测连通性，自动检测代理服务器.
func checkProxyUrl(urlStr string) bool {
	proxyFunc := ieproxy.GetProxyFunc()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: proxyFunc},
	}

	resp, err := client.Get(urlStr)
	if err != nil {
		// fmt.Printf("连通性错误 %s: %v\n", urlStr, err)
		return false
	}
	defer resp.Body.Close()

	// fmt.Println("成功连接: " + urlStr)
	return true
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
		body, _ := io.ReadAll(resp.Body) // 尝试读取响应体以获取更多错误信息
		return nil, fmt.Errorf("非预期的HTTP状态码: %v, 响应体: %s", resp.Status, string(body))
	}

	return io.ReadAll(resp.Body)
}

// autoSetFileName 自动检测输入文件格式并进行处理:
// defaultTxtFile为默认输入的txt文件名称，"ip.txt”（为*File默认参数），
// defaultZipFile为默认输入的zip文件名称，"ip.zip"（用户自定义）。
func autoSetFileName(defaultTxtFile string, defaultZipFile string) {
	ZipedFile := defaultZipFile
	if strings.HasSuffix(*File, ".txt") {
		// 如果ip文件格式为txt
		if *File == defaultTxtFile {
			// 如果ip文件参数为默认或未手动指定
			if _, err := os.Stat(*File); os.IsNotExist(err) {
				if _, err := os.Stat(ZipedFile); os.IsNotExist(err) {
					fmt.Println("未发现 默认ip列表 (支持txt和zip格式)")
					return
				}
				// 生成解压文件文件名
				UnZipedFile := "ip_" + "Default" + "_unZiped.txt"
				// 调用unZip2txt.go文件内的函数处理ZIP文件
				err := task.UnZip2txtFile(ZipedFile, UnZipedFile)
				if err != nil {
					panic(err)
				}
				*File = UnZipedFile
				fmt.Printf("\033[90m发现程序默认压缩包 %s,解压并合并ip文件: %s\033[0m\n", ZipedFile, *File)
			} else {
				fmt.Printf("\033[90m发现程序默认ip列表文件 %s\033[0m\n", *File)
			}
		} else {
			if _, err := os.Stat(*File); os.IsNotExist(err) {
				fmt.Println("未发现ip列表文件")
				return
			}
			fmt.Printf("\033[90m发现指定ip列表文件 %s\033[0m\n", *File)
		}
	} else if strings.HasSuffix(*File, ".zip") {
		// 如果ip文件格式为zip
		if _, err := os.Stat(*File); os.IsNotExist(err) {
			fmt.Println("未发现ip列表文件")
			return
		}
		fmt.Printf("\033[90m发现用户指定ip列表压缩包 %s\033[0m", *File)

		// 获取压缩包文件名
		ZipedFileName := strings.Split(*File, ".")[0]
		caser := cases.Title(language.English)      // 使用English作为默认语言标签
		ZipedFileName = caser.String(ZipedFileName) // 字母小写

		// 生成解压文件文件名
		UnZipedFile := "ip_" + ZipedFileName + "_unZiped.txt"
		// 调用unZip2txt.go文件内的函数处理ZIP文件
		err := task.UnZip2txtFile(*File, UnZipedFile)
		if err != nil {
			panic(err)
		}
		*File = UnZipedFile
		fmt.Printf("\033[90m,解压并合并ip文件: %s\033[0m\n", *File)
	} else {
		fmt.Println("\033[31m输入ip文件应为 txt 或 zip 格式，请重新输入\033[0m")
		return
	}
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
	// 弃用Dial，使用新的DialContext函数，这里context.Background()提供了一个空的上下文
	conn, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(ip, strconv.Itoa(*defaultPort)))
	if err != nil {
		return 0
	}
	defer conn.Close()

	fmt.Printf("正在测试IP %s 端口 %s\r", ip, strconv.Itoa(*defaultPort))
	startTime := time.Now()
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			// 使用新的DialContext函数
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		// 外网访问延迟较大，设置单个IP延迟最长时间为5秒
		Timeout: 5 * time.Second,
	}

	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("-IP %s 端口 %s \033[9m测速无效\033[0m\n", ip, strconv.Itoa(*defaultPort))
		return 0
	}
	defer resp.Body.Close()

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)

	speedOrignal := float64(written) / duration.Seconds() / (1024 * 1024) // 真实测速数据，如开多协程会有失真。单位MB/s
	// speed_KB := float64(written) / duration.Seconds() / 1024  //单位KB/s

	if *multipleNum == 1 || *speedTest < 5 {
		speed := float64(written) / duration.Seconds() / (1024 * 1024)
		// 输出结果
		fmt.Printf("-IP %s 端口 %s 下载速度 %.1f MB/s\n", ip, strconv.Itoa(*defaultPort), speed)
		return speed
	} else {
		// 多协程测速会有速度损失，加以补偿
		speed := float64(written) / duration.Seconds() / (1024 * 1024) * (*multipleNum)
		fmt.Printf("-IP %s 端口 %s 下载速度 %.1f MB/s, 补偿系数 %.0f, 原速度 %.1f MB/s\n", ip, strconv.Itoa(*defaultPort), speed, *multipleNum, speedOrignal)
		return speed
	}
}
