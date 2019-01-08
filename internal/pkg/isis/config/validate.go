package config

import (
	"errors"
	"regexp"

	"github.com/m-asama/golsr/internal/pkg/kernel"
)

func (config *NodeTag) validate() error {
	var err error
	return err
}

func (config *AddressFamily) validate() error {
	var err error
	return err
}

func (config *Topology) validate() error {
	var err error
	return err
}

func (config *InterfaceAddressFamily) validate() error {
	var err error
	return err
}

func (config *InterfaceTopology) validate() error {
	var err error
	return err
}

func (config *Interface) validate() error {
	var err error
	if config.Config.Name == nil {
		return errors.New("interface name not defined")
	}
	if !kernel.IfaceExists(*config.Config.Name) {
		return errors.New("interface not exists")
	}
	for _, af := range config.AddressFamilies {
		err = af.validate()
		if err != nil {
			return err
		}
	}
	for _, topo := range config.Topologies {
		err = topo.validate()
		if err != nil {
			return err
		}
	}
	return err
}

func (config *IsisConfig) validate() error {
	var err error
	if config.Config.SystemId == nil {
		return errors.New("system-id not defined")
	}
	err = validateSystemId(*config.Config.SystemId)
	if err != nil {
		return err
	}
	if len(config.Config.AreaAddress) == 0 {
		return errors.New("area-address-list not defined")
	}
	err = validateAreaAddress(config.Config.AreaAddress)
	if err != nil {
		return err
	}
	for _, nodeTag := range config.NodeTags {
		err = nodeTag.validate()
		if err != nil {
			return err
		}
	}
	for _, af := range config.AddressFamilies {
		err = af.validate()
		if err != nil {
			return err
		}
	}
	for _, topo := range config.Topologies {
		err = topo.validate()
		if err != nil {
			return err
		}
	}
	for _, iface := range config.Interfaces {
		err = iface.validate()
		if err != nil {
			return err
		}
	}
	return err
}

func validateSystemId(systemId string) error {
	validSystemId := regexp.MustCompile(`^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$`)
	if !validSystemId.MatchString(systemId) {
		return errors.New("system-id invalid")
	}
	return nil
}

func validateAreaAddress(areaAddresses []*string) error {
	validAreaAddress := regexp.MustCompile(`^[0-9A-Fa-f]{2}(\.[0-9A-Fa-f]{4}){0,3}$`)
	for _, areaAddress := range areaAddresses {
		if areaAddress == nil {
			return errors.New("area-address-list invalid")
		}
		if !validAreaAddress.MatchString(*areaAddress) {
			return errors.New("area-address-list invalid")
		}
	}
	return nil
}
