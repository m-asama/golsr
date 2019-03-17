package config

import (
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"testing"
)

func TestConfig(t *testing.T) {
	var err error
	config := []byte(`
[config]
  enable = true
  [authentication.config]
    key = "akey"
    crypto-algorithm = "ca"
    [authentication.level-1.config]
      key = "akey1"
      crypto-algorithm = "ca1"

[[address-families]]
  [address-families.config]
    address-family = "ipv4"
    enable = true

[[address-families]]
  [address-families.config]
    address-family = "ipv6"
    enable = true

[[interfaces]]
  [interfaces.config]
    name = "hoge"
    [[interfaces.address-families]]
      [interfaces.address-families.config]
        address-family = "ipv4"
    [[interfaces.address-families]]
      [interfaces.address-families.config]
        address-family = "ipv6"

[[interfaces]]
  [interfaces.config]
    name = "piyo"
`)
	c := &IsisConfig{}
	v := viper.New()
	v.SetConfigType("toml")
	err = v.ReadConfig(bytes.NewBuffer(config))
	if err != nil {
		t.Fatalf("failed ReadConfig: %#v", err)
	}
	err = v.UnmarshalExact(c)
	if err != nil {
		t.Fatalf("failed UnmarshalExact: %#v", err)
	}
	//t.Fatalf("%t", *c.Config.Enable)
	//t.Fatalf("*c.Interfaces[0].Config.Name = %s", *c.Interfaces[0].Config.Name)
	//t.Fatalf("*c.AddressFamilies[0].Config.AddressFamily = %s", *c.AddressFamilies[0].Config.AddressFamily)
	var ss []string
	for _, af := range c.AddressFamilies {
		ss = append(ss, fmt.Sprintf("*af.Config.AddressFamily = %s", *af.Config.AddressFamily))
	}
	//t.Fatalf("%s", ss)
	//t.Fatalf("xx = %s", *c.Interfaces[0].AddressFamilies[0].Config.AddressFamily)
}
