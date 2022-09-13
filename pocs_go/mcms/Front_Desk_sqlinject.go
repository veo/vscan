package mcms

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//mcms 5.2.7 /cms/content/list
func Front_Sql_inject(u string) bool {

	if req, err := pkg.HttpRequset(u+"/cms/content/list", "POST", "categoryId=1'", false, nil); err == nil {
		if strings.Contains(req.Body, "error in your SQL") {
			pkg.GoPocLog(fmt.Sprintf("Found mcms_sql_inject|\"%s\"\n", u+"/cms/content/list|POST:categoryId"))
			return true
		}
	}

	return false
}
