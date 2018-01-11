// Copyright 2017 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sensor

import (
	"sync"
	"sync/atomic"
)

type subscriptionUnregisterFn func(eventID uint64, sub *subscription)

type subscription struct {
	data       chan interface{}
	unregister subscriptionUnregisterFn
}

//
// safeSubscriptionMap
// map[uint64]map[uint64]*subscription
//

type subscriptionMap map[uint64]map[uint64]*subscription

func newSubscriptionMap() subscriptionMap {
	return make(subscriptionMap)
}

const dummySubscriptionID = ^uint64(0) // 0xffffffffffffffff

func (sm subscriptionMap) subscribe(eventID uint64) *subscription {
	im, ok := sm[eventID]
	if !ok {
		im = make(map[uint64]*subscription)
		sm[eventID] = im
	}
	if s, ok := im[dummySubscriptionID]; ok {
		return s
	}

	s := &subscription{}
	im[dummySubscriptionID] = s
	return s
}

func (sm subscriptionMap) forEach(f func(uint64, uint64, *subscription)) {
	for eventID, im := range sm {
		for subscriptionID, s := range im {
			f(eventID, subscriptionID, s)
		}
	}
}

type safeSubscriptionMap struct {
	sync.Mutex                      // used only by writers
	active             atomic.Value // map[uint64]map[uint64]*subscription
	nextSubscriptionID uint64
}

func newSafeSubscriptionMap() *safeSubscriptionMap {
	return &safeSubscriptionMap{}
}

func (ssm *safeSubscriptionMap) getMap() subscriptionMap {
	value := ssm.active.Load()
	if value == nil {
		return nil
	}
	return value.(subscriptionMap)
}

func (ssm *safeSubscriptionMap) subscribe(fm subscriptionMap) uint64 {
	ssm.Lock()
	defer ssm.Unlock()

	ssm.nextSubscriptionID++
	subscriptionID := ssm.nextSubscriptionID

	om := ssm.getMap()
	nm := make(subscriptionMap, len(om)+len(fm))

	if om != nil {
		for k, v := range om {
			c := make(map[uint64]*subscription, len(v))
			for k2, v2 := range v {
				c[k2] = v2
			}
			nm[k] = c
		}
	}

	for eventID, newSubscriptionMap := range fm {
		subscriptionMap, ok := nm[eventID]
		if !ok {
			subscriptionMap = make(map[uint64]*subscription)
			nm[eventID] = subscriptionMap
		}
		for _, s := range newSubscriptionMap {
			subscriptionMap[subscriptionID] = s
		}
	}

	ssm.active.Store(nm)
	return subscriptionID
}

func (ssm *safeSubscriptionMap) unsubscribe(
	subscriptionID uint64,
	f func(uint64),
) {
	var deadEventIDs []uint64
	deadSubscriptions := make(map[uint64]*subscription)

	ssm.Lock()

	om := ssm.getMap()
	if om != nil {
		nm := make(subscriptionMap, len(om))
		for eventID, v := range om {
			var m map[uint64]*subscription
			for ID, s := range v {
				if ID != subscriptionID {
					if m == nil {
						m = make(map[uint64]*subscription)
					}
					m[ID] = s
				} else if s.unregister != nil {
					deadSubscriptions[eventID] = s
				}
			}
			if m == nil {
				deadEventIDs = append(deadEventIDs, eventID)
			} else {
				nm[eventID] = m
			}
		}
		ssm.active.Store(nm)
	}

	ssm.Unlock()

	for eventID, s := range deadSubscriptions {
		s.unregister(eventID, s)
	}
	if f != nil {
		for _, eventID := range deadEventIDs {
			f(eventID)
		}
	}
}
