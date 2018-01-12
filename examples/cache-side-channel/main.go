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

package main

import (
	"flag"
	"runtime"
	"log"

	"github.com/capsule8/capsule8/pkg/sys/perf"
)

const (
	// How many cache loads to sample on. After each sample period
	// of this many cache loads, the cache miss rate is calculated
	// and examined. This value tunes the trade-off between CPU
	// load and detection accuracy.
	LLCLoadSampleSize = 10000

	// Alarm thresholds as cache miss rates (between 0 and 1).
	// These values tune the trade-off between false negatives and
	// false positives.
	alarmThresholdInfo    = 0.97
	alarmThresholdWarning = 0.98
	alarmThresholdError   = 0.99

	// perf_event_attr config value for LL cache loads
	perfConfigLLCLoads = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16)

	// perf_event_attr config value for LL cache misses
	perfConfigLLCLoadMisses = perf.PERF_COUNT_HW_CACHE_LL |
		(perf.PERF_COUNT_HW_CACHE_OP_READ << 8) |
		(perf.PERF_COUNT_HW_CACHE_RESULT_MISS << 16)
)

type eventCounters struct {
	LLCLoads      uint64
	LLCLoadMisses uint64
}

var cpuCounters []eventCounters

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	log.Println("Starting Capsule8 cache side channel detector")

	//
	// Create our event group to read LL cache accesses and misses
	//
	// We ask the kernel to sample every LLCLoadSampleSize LLC
	// loads. During each sample, the LLC load misses are also
	// recorded, as well as CPU number, PID/TID, and sample time.
	//
	eventGroup := []*perf.EventAttr{}

	ea := &perf.EventAttr{
		Disabled: true,
		Type:     perf.PERF_TYPE_HW_CACHE,
		Config:   perfConfigLLCLoads,
		SampleType: perf.PERF_SAMPLE_CPU | perf.PERF_SAMPLE_STREAM_ID |
			perf.PERF_SAMPLE_TID | perf.PERF_SAMPLE_READ | perf.PERF_SAMPLE_TIME,
		ReadFormat:   perf.PERF_FORMAT_GROUP | perf.PERF_FORMAT_ID,
		Pinned:       true,
		SamplePeriod: LLCLoadSampleSize,
		WakeupEvents: 1,
	}
	eventGroup = append(eventGroup, ea)

	ea = &perf.EventAttr{
		Disabled: true,
		Type:     perf.PERF_TYPE_HW_CACHE,
		Config:   perfConfigLLCLoadMisses,
	}
	eventGroup = append(eventGroup, ea)

	eg, err := perf.NewEventGroup(eventGroup)
	if err != nil {
		log.Fatal(err)
	}

	//
	// Open the event group on all CPUs
	//
	err = eg.Open()
	if err != nil {
		log.Fatal(err)
	}

	// Allocate counters per CPU
	cpuCounters = make([]eventCounters, runtime.NumCPU())

	log.Println("Monitoring for cache side channels")
	eg.Run(func(sample perf.Sample) {
		sr, ok := sample.Record.(*perf.SampleRecord)
		if ok {
			onSample(sr, eg.EventAttrsByID)
		}
	})
}

func onSample(sr *perf.SampleRecord, eventAttrMap map[uint64]*perf.EventAttr) {
	var counters eventCounters

	// The sample record contains all values in the event group,
	// tagged with their event ID
	for _, v := range sr.V.Values {
		ea := eventAttrMap[v.ID]

		if ea.Config == perfConfigLLCLoads {
			counters.LLCLoads = v.Value
		} else if ea.Config == perfConfigLLCLoadMisses {
			counters.LLCLoadMisses = v.Value
		}
	}

	cpu := sr.CPU
	prevCounters := cpuCounters[cpu]
	cpuCounters[cpu] = counters

	counterDeltas := eventCounters{
		LLCLoads:      counters.LLCLoads - prevCounters.LLCLoads,
		LLCLoadMisses: counters.LLCLoadMisses - prevCounters.LLCLoadMisses,
	}

	alarm(sr, counterDeltas)
}

func alarm(sr *perf.SampleRecord, counters eventCounters) {
	LLCLoadMissRate := float32(counters.LLCLoadMisses) / float32(counters.LLCLoads)

	if LLCLoadMissRate > alarmThresholdError {
		log.Println("Error: cpu=%v pid=%v tid=%v LLCLoadMissRate=%v",
			sr.CPU, sr.Pid, sr.Tid, LLCLoadMissRate)
	} else if LLCLoadMissRate > alarmThresholdWarning {
		log.Println("WARNING: cpu=%v pid=%v tid=%v LLCLoadMissRate=%v",
			sr.CPU, sr.Pid, sr.Tid, LLCLoadMissRate)
	} else if LLCLoadMissRate > alarmThresholdInfo {
		log.Println("INFO: cpu=%v pid=%v tid=%v LLCLoadMissRate=%v",
			sr.CPU, sr.Pid, sr.Tid, LLCLoadMissRate)
	}
}
