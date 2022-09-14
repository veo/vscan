package main

import (
	"github.com/projectdiscovery/gologger"
	naabuRunner "github.com/veo/vscan/pkg/naabu/v2/pkg/runner"
	"runtime"
)

func main() {
	options := naabuRunner.ParseOptions()
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	runner, err := naabuRunner.NewRunner(options)

	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	err = runner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
	gologger.Info().Msg("Port scan over,web scan starting")
	err = runner.Httpxrun()
	if err != nil {
		gologger.Fatal().Msgf("Could not run httpRunner: %s\n", err)
	}
}
