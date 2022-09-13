package tools


func Start(Addr string,Port string){
	cfg := &Cfg{
		Addr: Addr,
		Port: Port,
		IsAnonymous: false,
		Debug: false,
	}
	Run(cfg)
}