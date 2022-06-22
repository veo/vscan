package check

import (
	"embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/veo/vscan/pkg"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/parse"
	"github.com/veo/vscan/pocs_yml/pkg/nuclei/templates"
	"sync"
)

func LoadTemplatesWithTags(templatesList, tags []string, ExcludeTags []string, Pocs embed.FS) []*templates.Template {
	tagFilter := filter.New(&filter.Config{
		Tags:        []string{},
		ExcludeTags: ExcludeTags,
		Authors:     []string{},
		IncludeTags: []string{},
		IncludeIds:  []string{},
		ExcludeIds:  []string{},
	})
	pathFilter := filter.NewPathFilter(&filter.PathFilterConfig{
		IncludedTemplates: []string{},
		ExcludedTemplates: []string{},
	}, nil)

	templatePathMap := pathFilter.Match(templatesList)

	loadedTemplates := make([]*templates.Template, 0, len(templatePathMap))
	for templatePath := range templatePathMap {
		loaded, err := parse.LoadTemplate(templatePath, tagFilter, tags, Pocs)
		if err != nil {
			gologger.Warning().Msgf("Could not load template %s: %s\n", templatePath, err)
		}
		if loaded {
			poc, err := parse.ParsePoc(templatePath, Pocs)
			if err != nil {
				gologger.Warning().Msgf("Could not parse template %s: %s\n", templatePath, err)
				return nil
			} else if poc != nil {
				loadedTemplates = append(loadedTemplates, poc)
			}
		}
	}
	return loadedTemplates
}

func execute(template *templates.Template, URL string) bool {
	templateType := template.Type()
	if templateType == types.HTTPProtocol {
		match, err := template.Executer.Execute(URL)
		if err != nil {
			gologger.Warning().Msgf("[%s] Could not execute step: %s\n", template.ID, err)
		}
		if match {
			return true
		}
	}
	return false
}

func NucleiStart(target string, template []*templates.Template) []string {
	var WaitGroup sync.WaitGroup
	var Vullist []string
	for _, t := range template {
		WaitGroup.Add(1)
		go func(t *templates.Template) {
			if execute(t, target) {
				pkg.NucleiLog(fmt.Sprintf("%s (%s)\n", target, t.ID))
				Vullist = append(Vullist, "NucleiPOC_"+t.ID)
			}
			WaitGroup.Done()
		}(t)
	}
	WaitGroup.Wait()
	return Vullist
}
