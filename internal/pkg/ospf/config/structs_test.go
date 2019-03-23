//
// Copyright (C) 2019-2019 Masakazu Asama.
// Copyright (C) 2019-2019 Ginzado Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
[[areas]]
  [areas.config]
    area-id = "0.0.0.0"
    [[areas.interfaces]]
      [areas.interfaces.config]
        name = "eth0"
[[areas]]
  [areas.config]
    area-id = "0.0.0.1"
    [[areas.interfaces]]
      [areas.interfaces.config]
        name = "eth1"
`)
	c := &OspfConfig{}
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
	var ss []string
	for _, area := range c.Areas {
		ss = append(ss, fmt.Sprintf("*area.Config.AreaId = %s", *area.Config.AreaId))
	}
	//t.Fatalf("%s", ss)
}
