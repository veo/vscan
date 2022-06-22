package pocs_yml

import (
	"embed"
	"github.com/projectdiscovery/gologger"
	"github.com/veo/vscan/pocs_yml/check"
	common_structs "github.com/veo/vscan/pocs_yml/pkg/common/structs"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/catalog"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/parse"
	xray_requests "github.com/veo/vscan/pocs_yml/pkg/xray/requests"
	"github.com/veo/vscan/pocs_yml/utils"
	"time"
)

//go:embed xrayFiles
var XrayPocs embed.FS

//go:embed nucleiFiles
var NucleiPocs embed.FS

func XrayCheck(target string, ceyeapi string, ceyedomain string, proxy string, pocname string) []string {
	common_structs.InitReversePlatform(ceyeapi, ceyedomain)
	_ = xray_requests.InitHttpClient(10, proxy, time.Duration(5)*time.Second)
	xrayPocs := utils.LoadMultiPoc(XrayPocs, pocname)
	xrayTotalReqeusts := 0
	for _, poc := range xrayPocs {
		ruleLens := len(poc.Rules)
		if poc.Transport == "tcp" || poc.Transport == "udp" {
			ruleLens += 1
		}
		xrayTotalReqeusts += 1 * ruleLens
	}
	if xrayTotalReqeusts == 0 {
		xrayTotalReqeusts = 1
	}
	xray_requests.InitCache(xrayTotalReqeusts)
	return check.XrayStart(target, xrayPocs)
}

func NucleiCheck(target string, ceyeapi string, ceyedomain string, proxy string, Tags []string) []string {
	parse.InitExecuterOptions(100, 5)
	list, err := catalog.New("").GetTemplatePath(NucleiPocs)
	if err != nil {
		gologger.Error().Msgf("Could not find template: %s\n", err)
	}
	ExcludeTags := []string{"apache", "java", "php"}
	templatesList := check.LoadTemplatesWithTags(list, Tags, ExcludeTags, NucleiPocs)
	return check.NucleiStart(target, templatesList)
}
