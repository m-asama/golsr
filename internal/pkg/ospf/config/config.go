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
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	//yaml "gopkg.in/yaml.v2"
)

func detectConfigFileType(path, def string) string {
	switch ext := filepath.Ext(path); ext {
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		return def
	}
}

func Serve(path, format string, configCh chan *OspfConfig) {

	//log.Info("ReadConfigfileServe started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	// Update config file type, if detectable
	format = detectConfigFileType(path, format)

	cnt := 0
	for {
		c := &OspfConfig{}
		v := viper.New()
		v.SetConfigFile(path)
		v.SetConfigType(format)
		var err error
		if err = v.ReadInConfig(); err != nil {
			goto ERROR
		}
		if err = v.UnmarshalExact(c); err != nil {
			goto ERROR
		}
		c.fillDefaults()
		if err = c.validate(); err != nil {
			goto ERROR
		}
		if cnt == 0 {
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Info("Finished reading the config file")
		}
		/*
			if err = v.WriteConfigAs("/tmp/goospfd.toml"); err != nil {
				log.Info("WriteConfigAs failed", err)
			} else {
				log.Info("WriteConfigAs success")
			}
			bs, err = yaml.Marshal(c)
			if err != nil {
				log.Info("yaml.Marshal error")
			} else {
				fmt.Printf("\n%s", string(bs))
			}
		*/

		cnt++
		configCh <- c
		goto NEXT
	ERROR:
		if cnt == 0 {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Fatalf("Can't read config file %s", path)
		} else {
			log.WithFields(log.Fields{
				"Topic": "Config",
				"Error": err,
			}).Warningf("Can't read config file %s", path)
		}
	NEXT:
		<-sigCh
		log.WithFields(log.Fields{
			"Topic": "Config",
		}).Info("Reload the config file")
	}
}
