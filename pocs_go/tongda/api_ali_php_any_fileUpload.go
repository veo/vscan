package tongda

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//version 通达 OA V11.8 api.ali.php 任意文件上传
func File_upload(url string) bool{
	if req, err := pkg.HttpRequset(url+"/mobile/api/api.ali.php", "GET", "", false, nil); err == nil {
		if req.StatusCode==200{
			pkg.GoPocLog(fmt.Sprintf("Found vuln tongda-OA upload in api.ali.php | \"%s\"\n", url))
			return true
		}
	}
	return false
}