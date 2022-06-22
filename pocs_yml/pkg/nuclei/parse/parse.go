package parse

import (
	"embed"
	"errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/templates"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/structs"

	"go.uber.org/ratelimit"
)

var (
	ExecuterOptions protocols.ExecuterOptions
)

func InitExecuterOptions(rate int, timeout int) {
	fakeWriter := structs.FakeWrite{}
	progress := &structs.FakeProgress{}
	o := types.Options{
		RateLimit:               rate,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		HeadlessTemplateThreads: 10,
		Timeout:                 timeout,
		Retries:                 1,
		MaxHostError:            30,
	}
	err := protocolinit.Init(&o)
	if err != nil {
		gologger.Error().Msgf("Nuclei InitExecuterOptions error")
		return
	}

	catalog2 := catalog.New("")
	ExecuterOptions = protocols.ExecuterOptions{
		Output:      &fakeWriter,
		Options:     &o,
		Progress:    progress,
		Catalog:     catalog2,
		RateLimiter: ratelimit.New(rate),
	}

}

func ParsePoc(filename string, Pocs embed.FS) (*templates.Template, error) {
	var err error
	poc, err := templates.Parse(filename, nil, ExecuterOptions, Pocs)
	if err != nil {
		return nil, err
	}
	if poc == nil {
		return nil, nil
	}
	if poc.ID == "" {
		return nil, errors.New("Nuclei poc id can't be nil")
	}
	return poc, nil
}
