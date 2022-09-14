package tools

//被动扫描
import (

"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/veo/vscan/pocs_session"
	"io"
"log"
"net"
"net/http"
"strings"
)

type Pxy struct {
	Cfg Cfg
	Hostlist string
}

// 设置type
type Cfg struct {
	Addr        string   // 监听地址
	Port        string   // 监听端口
	IsAnonymous bool     // 高匿名模式
	Debug       bool     // 调试模式
}


func Run(cfg *Cfg) {
	pxy := NewPxy()
	pxy.SetPxyCfg(cfg)
	log.Printf("HttpPxoy is runing on %s:%s \n", cfg.Addr, cfg.Port)
	// http.Handle("/", pxy)
	bindAddr := cfg.Addr + ":" + cfg.Port
	log.Fatalln(http.ListenAndServe(bindAddr, pxy))
}


// 实例化
func NewPxy() *Pxy {
	return &Pxy{
		Cfg: Cfg{
			Addr:        "",
			Port:        "8081",
			IsAnonymous: true,
			Debug:       false,
		},
	}
}

// 配置参数
func (p *Pxy) SetPxyCfg(cfg *Cfg) {
	if cfg.Addr != "" {
		p.Cfg.Addr = cfg.Addr
	}
	if cfg.Port != "" {
		p.Cfg.Port = cfg.Port
	}
	if cfg.IsAnonymous != p.Cfg.IsAnonymous {
		p.Cfg.IsAnonymous = cfg.IsAnonymous
	}
	if cfg.Debug != p.Cfg.Debug {
		p.Cfg.Debug = cfg.Debug
	}

}
func (p *Pxy)Scanaddress(address string)  {
	fmt.Println("start scan on " + address)


}
// 运行代理服务
func (p *Pxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// debug
	if p.Cfg.Debug {
		log.Printf("Received request %s %s %s\n", req.Method, req.Host, req.RemoteAddr)
		// fmt.Println(req)
	}

	target:=req.Host
	index:=strings.Contains(p.Hostlist,target)

	var Vullist []string
	builder := &strings.Builder{}
	if !index{

		p.Hostlist += target + "\n"

		//开始扫描
		var url string
		if strings.Contains(target,":443"){
			url="https://"+strings.Replace(target,":443","",-1)
		}else{
			url="http://"+target
		}

		technology := pocs_session.POCcheck(url,req)
		Vullist = append(Vullist,technology...)

		if len(Vullist) > 0 {
			Vullist := strings.Join(Vullist, "\",\"")
			builder.WriteString(" [")

			builder.WriteString(aurora.Red("SESSION_POC:").String())
			builder.WriteString(aurora.Red("\"" + Vullist + "\"").String())

			builder.WriteRune(']')
		}

	}



	// http && https
	if req.Method != "CONNECT" {
		// 处理http
		p.HTTP(rw, req)
	} else {
		// 处理https
		// 直通模式不做任何中间处理
		p.HTTPS(rw, req)
	}

}

// http
func (p *Pxy) HTTP(rw http.ResponseWriter, req *http.Request) {

	transport := http.DefaultTransport

	// 新建一个请求outReq
	outReq := new(http.Request)
	// 复制客户端请求到outReq上
	*outReq = *req // 复制请求

	//  处理匿名代理
	if p.Cfg.IsAnonymous == false {
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			if prior, ok := outReq.Header["X-Forwarded-For"]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			outReq.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	// outReq请求放到传送上
	res, err := transport.RoundTrip(outReq)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		rw.Write([]byte(err.Error()))
		return
	}

	// 回写http头
	for key, value := range res.Header {
		for _, v := range value {
			rw.Header().Add(key, v)
		}
	}
	// 回写状态码
	rw.WriteHeader(res.StatusCode)
	// 回写body
	io.Copy(rw, res.Body)
	res.Body.Close()
}


// https
func (p *Pxy) HTTPS(rw http.ResponseWriter, req *http.Request) {

	// 拿出host
	host := req.URL.Host

	hij, ok := rw.(http.Hijacker)

	if !ok {
		log.Printf("HTTP Server does not support hijacking")
	}

	client, _, err := hij.Hijack()
	if err != nil {
		return
	}

	// 连接远程
	server, err := net.Dial("tcp", host)
	if err != nil {
		return
	}
	client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))

	// 直通双向复制
	go io.Copy(server, client)
	go io.Copy(client, server)
}
