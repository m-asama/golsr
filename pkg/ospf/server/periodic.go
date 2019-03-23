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

package server

import (
	"time"

	log "github.com/sirupsen/logrus"
)

func (ospf *OspfServer) periodic(doneCh chan struct{}) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	timer := time.NewTimer(0)
	started := time.Now()
	var counter time.Duration
	for {
		select {
		case <-doneCh:
			goto EXIT
		case <-timer.C:
			counter++
			timer.Reset(started.Add(time.Second * counter).Sub(time.Now()))
		}
	}
EXIT:
}
