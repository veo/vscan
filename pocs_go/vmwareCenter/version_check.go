package vmwareCenter

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
)

// 查看详细版本 author:penson

func VersionCheck(url string) bool {

	xml:="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<soap:Envelope\n    xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"\n    xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"\n    xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n    <soap:Header>\n        <operationID>00000001-00000001</operationID>\n    </soap:Header>\n    <soap:Body>\n        <RetrieveServiceContent\n            xmlns=\"urn:internalvim25\">\n            <_this xsi:type=\"ManagedObjectReference\" type=\"ServiceInstance\">ServiceInstance</_this>\n        </RetrieveServiceContent>\n    </soap:Body>\n</soap:Envelope>"

	if req, err := pkg.HttpRequset(url+"/sdk", "POST", xml, false, nil); err == nil {
		re := regexp.MustCompile("<fullName>(.*?)</fullName>")
		version:=re.FindStringSubmatch(req.Body)[1]
		pkg.GoPocLog(fmt.Sprintf("Found version vmwmareCenter | \"%s\"\n", url+" "+version))
		return true
	}
	return false
}
