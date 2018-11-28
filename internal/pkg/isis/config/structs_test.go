package config

import (
	"bytes"
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

[[interfaces]]
  [interfaces.config]
    name = "hoge"

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
	t.Fatalf("*c.Interfaces[0].Config.Name = %s", *c.Interfaces[0].Config.Name)
}
