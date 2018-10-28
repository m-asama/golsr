package main

import (
	"fmt"
	"github.com/m-asama/golsr/internal/pkg/isis/config"
)

func main() {
	fmt.Println("MAIN")
	configCh := make(chan *config.IsisConfig)
	go config.ReadConfigfileServe("test.toml", "toml", configCh)
	c := <-configCh
	if c.Config.Enable != nil {
		fmt.Println(*c.Config.Enable)
	}
	if c.Config.LevelType != nil {
		fmt.Println(*c.Config.LevelType)
	}
	if c.Authentication.Config.Key != nil {
		fmt.Println("c.Authentication.Config.Key", *c.Authentication.Config.Key)
	}
	if c.Authentication.Level1.Config.Key != nil {
		fmt.Println("c.Authentication.Level1.Config.Key", *c.Authentication.Level1.Config.Key)
	}
	for i, v := range c.Config.AreaAddress {
		fmt.Print(i)
		fmt.Print(" : ")
		fmt.Print(v)
		fmt.Println("")
	}
	for i, v := range c.Interfaces {
		fmt.Print(i)
		fmt.Print(" : ")
		if v.Config.Name != nil {
			fmt.Print(*v.Config.Name)
		}
		fmt.Println("")
	}
}
