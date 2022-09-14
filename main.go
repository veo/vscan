package main

import (
	"github.com/projectdiscovery/gologger"
	naabuRunner "github.com/veo/vscan/pkg/naabu/v2/pkg/runner"
	"github.com/veo/vscan/tools"
	"runtime"
)

func main() {
	options := naabuRunner.ParseOptions()
	if runtime.GOOS == "windows" {
		options.NoColor = true
	}
	runner, err := naabuRunner.NewRunner(options)

	if options.ListenPort!="-1"{
		//开启被动模式
		tools.Start(options.ListenIp,options.ListenPort)
	}
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
