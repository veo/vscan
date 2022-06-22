package structs

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

type FakeWrite struct{}

func (r *FakeWrite) WriteStoreDebugData(host, templateID, eventType string, data string) {
}

func (r *FakeWrite) Close() {}
func (r *FakeWrite) Colorizer() aurora.Aurora {
	return nil
}
func (r *FakeWrite) WriteFailure(event output.InternalEvent) error          { return nil }
func (r *FakeWrite) Write(w *output.ResultEvent) error                      { return nil }
func (r *FakeWrite) Request(templateID, url, requestType string, err error) {}

type FakeProgress struct{}

func (p *FakeProgress) Stop()                                                    {}
func (p *FakeProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (p *FakeProgress) AddToTotal(delta int64)                                   {}
func (p *FakeProgress) IncrementRequests()                                       {}
func (p *FakeProgress) IncrementMatched()                                        {}
func (p *FakeProgress) IncrementErrorsBy(count int64)                            {}
func (p *FakeProgress) IncrementFailedRequestsBy(count int64)                    {}
