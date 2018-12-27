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

func ReadConfigfileServe(path, format string, configCh chan *IsisConfig) {

	//log.Info("ReadConfigfileServe started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	// Update config file type, if detectable
	format = detectConfigFileType(path, format)

	cnt := 0
	for {
		c := &IsisConfig{}
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
			if err = v.WriteConfigAs("/tmp/goisisd.toml"); err != nil {
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
