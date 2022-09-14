package pocs_session

import (
	"fmt"
	"github.com/veo/vscan/pocs_session/mcms"
	"net/http"
)

func POCcheck( URL string,req *http.Request) []string {

	var technologies []string


	if(mcms.Backstage_sqlinject_1(URL,req)){
		technologies=append(technologies, fmt.Sprintf("found backstaget_sqli|:%s",URL+"POST:categoryId"))
	}

	return technologies
}
