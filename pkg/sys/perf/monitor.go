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

package perf

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/capsule8/capsule8/pkg/config"
	"github.com/capsule8/capsule8/pkg/sys"
	"github.com/golang/glog"

	"golang.org/x/sys/unix"
)

type eventMonitorOptions struct {
	flags              uintptr
	defaultEventAttr   *EventAttr
	perfEventDir       string
	tracingDir         string
	ringBufferNumPages int
	cgroups            []string
	pids               []int
}

// EventMonitorOption is used to implement optional arguments for
// NewEventMonitor. It must be exported, but it is not typically
// used directly.
type EventMonitorOption func(*eventMonitorOptions)

// WithFlags is used to set optional flags when creating a new EventMonitor.
// The flags are passed to the low-level perf_event_open() system call.
func WithFlags(flags uintptr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.flags = flags
	}
}

// WithDefaultEventAttr is used to set an optional EventAttr struct to be used
// by default when registering events and no EventAttr is specified as part of
// the registration.
func WithDefaultEventAttr(defaultEventAttr *EventAttr) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.defaultEventAttr = defaultEventAttr
	}
}

// WithPerfEventDir is used to set an optional directory to use for monitoring
// cgroups. This should only be necessary if the perf_event cgroup fs is not
// mounted in the usual location.
func WithPerfEventDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.perfEventDir = dir
	}
}

// WithTracingDir is used to set an alternate mountpoint to use for managing
// tracepoints, kprobes, and uprobes.
func WithTracingDir(dir string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.tracingDir = dir
	}
}

// WithRingBufferNumPages is used to set the size of the ringbuffers used to
// retrieve samples from the kernel.
func WithRingBufferNumPages(numPages int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.ringBufferNumPages = numPages
	}
}

// WithCgroup is used to add a cgroup to the set of sources to monitor.
func WithCgroup(cgroup string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroup)
	}
}

// WithCgroups is used to add a list of cgroups to the set of sources to
// monitor.
func WithCgroups(cgroups []string) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.cgroups = append(o.cgroups, cgroups...)
	}
}

// WithPid is used to add a pid to the set of sources to monitor.
func WithPid(pid int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pid)
	}
}

// WithPids is used to add a list of pids to the set of sources to monitor.
func WithPids(pids []int) EventMonitorOption {
	return func(o *eventMonitorOptions) {
		o.pids = append(o.pids, pids...)
	}
}

type registerEventOptions struct {
	disabled  bool
	eventAttr *EventAttr
	filter    string
}

// RegisterEventOption is used to implement optional arguments for event
// registration methods. It must be exported, but it is not typically used
// directly.
type RegisterEventOption func(*registerEventOptions)

// WithEventDisabled is used to register the event in a disabled state.
func WithEventDisabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = true
	}
}

// WithEventEnabled is used to register the event in an enabled state.
func WithEventEnabled() RegisterEventOption {
	return func(o *registerEventOptions) {
		o.disabled = false
	}
}

// WithEventAttr is used to register the event with an EventAttr struct
// instead of using the EventMonitor's default.
func WithEventAttr(eventAttr *EventAttr) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.eventAttr = eventAttr
	}
}

// WithFilter is used to set a filter for the event.
func WithFilter(filter string) RegisterEventOption {
	return func(o *registerEventOptions) {
		o.filter = filter
	}
}

const (
	eventTypeTracepoint int = iota
	eventTypeKprobe
	eventTypeUprobe
)

type registeredEvent struct {
	name      string
	fds       []int
	eventType int
}

type perfEventGroup struct {
	rb         *ringBuffer
	timeBase   uint64
	timeOffset uint64
	pid        int // passed as 'pid' argument to perf_event_open()
	cpu        int // passed as 'cpu' argument to perf_event_open()
	fd         int // fd returned from perf_event_open()
	flags      uintptr
}

func (group *perfEventGroup) cleanup() {
	if group.rb != nil {
		group.rb.unmap()
	}
	unix.Close(group.fd)
	if group.flags&PERF_FLAG_PID_CGROUP == PERF_FLAG_PID_CGROUP {
		unix.Close(group.pid)
	}
}

// SampleDispatchFn is the signature of a function called to dispatch a
// sample. The first argument is the event ID, the second is the returned
// value from the decoder, and the third is the error that may have been
// returned from the decoder.
type SampleDispatchFn func(uint64, interface{}, error)

// EventMonitor is a high-level interface to the Linux kernel's perf_event
// infrastructure.
type EventMonitor struct {
	// Ordering of fields is intentional to keep the most frequently used
	// fields together at the head of the struct in an effort to increase
	// cache locality

	// Immutable items. No protection required. These fields are all set
	// when the EventMonitor is created and never changed after that.
	groups       map[int]perfEventGroup // fd : group data
	dispatchChan chan decodedSampleList

	// Mutable by various goroutines, and also needed by the monitor
	// goroutine. All of these are thread-safe mutable without a lock.
	// The monitor goroutine only ever reads from them, so there's no lock
	// taken. The thread-safe mutation of .decoders is handled elsewhere.
	// The other safe maps will lock if the monitor goroutine is running;
	// otherwise, .lock protects in-place writes.
	eventAttrMap *safeEventAttrMap // stream id : event attr
	eventIDMap   *safeUInt64Map    // stream id : event id
	decoders     *traceEventDecoderMap

	// Mutable only by the monitor goroutine while running. No protection
	// required.
	samples        decodedSampleList // Used while reading from ringbuffers
	pendingSamples decodedSampleList

	// Immutable once set. Only used by the .dispatchSamples() goroutine.
	// Load once there and cache locally to avoid cache misses on this
	// struct.
	dispatchFn SampleDispatchFn

	// This lock protects everything mutable below this point.
	lock *sync.Mutex

	// Mutable only by the monitor goroutine, but readable by others
	isRunning bool
	pipe      [2]int

	// Mutable by various goroutines, but not required by the monitor goroutine
	nextEventID uint64
	nextProbeID uint64
	events      map[uint64]registeredEvent // event id : event
	eventfds    map[int]int                // fd : cpu index
	eventids    map[int]uint64             // fd : stream id

	// Immutable, used only when adding new tracepoints/probes
	defaultAttr EventAttr
	tracingDir  string

	// Used only once during shutdown
	cond *sync.Cond
	wg   sync.WaitGroup
}

func fixupEventAttr(eventAttr *EventAttr) {
	// Adjust certain fields in eventAttr that must be set a certain way
	eventAttr.Type = PERF_TYPE_TRACEPOINT
	eventAttr.Size = sizeofPerfEventAttr
	eventAttr.SamplePeriod = 1 // SampleFreq not used
	eventAttr.SampleType |= PERF_SAMPLE_STREAM_ID | PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_TIME

	eventAttr.Disabled = true
	eventAttr.Pinned = false
	eventAttr.Freq = false
	eventAttr.Watermark = true
	eventAttr.UseClockID = false
	eventAttr.WakeupWatermark = 1 // WakeupEvents not used
}

func (monitor *EventMonitor) writeTraceCommand(name string, cmd string) error {
	filename := filepath.Join(monitor.tracingDir, name)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		glog.Fatalf("Couldn't open %s WO+A: %s", filename, err)
	}
	defer file.Close()

	_, err = file.Write([]byte(cmd))
	return err
}

func normalizeFetchargs(args string) string {
	// Normalize the output string so we can match it later
	args = strings.TrimSpace(args)
	if strings.Index(args, "  ") != -1 {
		parts := strings.Split(args, " ")
		result := make([]string, 0, len(parts))
		for _, s := range parts {
			if len(s) > 0 {
				result = append(result, s)
			}
		}
		args = strings.Join(result, " ")
	}

	return args
}

func (monitor *EventMonitor) addKprobe(name string, address string, onReturn bool, output string) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s %s", name, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s %s", name, address, output)
	}

	glog.V(1).Infof("Adding kprobe: '%s'", definition)
	return monitor.writeTraceCommand("kprobe_events", definition)
}

func (monitor *EventMonitor) removeKprobe(name string) error {
	return monitor.writeTraceCommand("kprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) addUprobe(name string, bin string, address string, onReturn bool, output string) error {
	output = normalizeFetchargs(output)

	var definition string
	if onReturn {
		definition = fmt.Sprintf("r:%s %s:%s %s", name, bin, address, output)
	} else {
		definition = fmt.Sprintf("p:%s %s:%s %s", name, bin, address, output)
	}

	glog.V(1).Infof("Adding uprobe: '%s'", definition)
	return monitor.writeTraceCommand("uprobe_events", definition)
}

func (monitor *EventMonitor) removeUprobe(name string) error {
	return monitor.writeTraceCommand("uprobe_events",
		fmt.Sprintf("-:%s", name))
}

func (monitor *EventMonitor) newProbeName() string {
	monitor.nextProbeID++
	return fmt.Sprintf("capsule8/sensor_%d_%d", unix.Getpid(),
		monitor.nextProbeID)
}

func (monitor *EventMonitor) perfEventOpen(eventAttr *EventAttr, filter string) ([]int, error) {
	glog.V(2).Infof("Opening perf event: %d %s", eventAttr.Config, filter)

	newfds := make([]int, 0, len(monitor.groups))
	for groupfd, group := range monitor.groups {
		flags := group.flags | PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP
		fd, err := open(eventAttr, group.pid, group.cpu, groupfd, flags)
		if err != nil {
			for j := len(newfds) - 1; j >= 0; j-- {
				unix.Close(newfds[j])
			}
			return nil, err
		}
		newfds = append(newfds, fd)

		if len(filter) > 0 {
			err := setFilter(fd, filter)
			if err != nil {
				for j := len(newfds) - 1; j >= 0; j-- {
					unix.Close(newfds[j])
				}
				return nil, err
			}
		}
	}

	return newfds, nil
}

// This should be called with monitor.lock held.
func (monitor *EventMonitor) newRegisteredEvent(name string, fn TraceEventDecoderFn, opts registerEventOptions, eventType int) (uint64, error) {
	id, err := monitor.decoders.AddDecoder(name, fn)
	if err != nil {
		return 0, err
	}

	var attr EventAttr

	if opts.eventAttr == nil {
		attr = monitor.defaultAttr
	} else {
		attr = *opts.eventAttr
		fixupEventAttr(&attr)
	}
	attr.Config = uint64(id)
	attr.Disabled = opts.disabled

	newfds, err := monitor.perfEventOpen(&attr, opts.filter)
	if err != nil {
		monitor.decoders.RemoveDecoder(name)
		return 0, err
	}

	// Choose the eventid for this event now, but don't commit to it until
	// later when no error has occurred in registering the event.
	eventid := monitor.nextEventID

	eventAttrMap := newEventAttrMap()
	eventIDMap := newUInt64Map()
	for _, fd := range newfds {
		streamid, err := unix.IoctlGetInt(fd, PERF_EVENT_IOC_ID)
		if err != nil {
			for _, fd := range newfds {
				unix.Close(fd)
				delete(monitor.eventids, fd)
			}
			monitor.decoders.RemoveDecoder(name)
			return 0, err
		}
		eventAttrMap[uint64(streamid)] = &attr
		eventIDMap[uint64(streamid)] = eventid
		monitor.eventids[fd] = uint64(streamid)
	}

	// Now is the time to commit to the eventid
	monitor.nextEventID++
	if monitor.isRunning {
		monitor.eventAttrMap.update(eventAttrMap)
		monitor.eventIDMap.update(eventIDMap)
	} else {
		monitor.eventAttrMap.updateInPlace(eventAttrMap)
		monitor.eventIDMap.updateInPlace(eventIDMap)
	}
	for i, fd := range newfds {
		monitor.eventfds[fd] = i
	}

	event := registeredEvent{
		name:      name,
		fds:       newfds,
		eventType: eventType,
	}

	monitor.events[eventid] = event
	return eventid, nil
}

// RegisterTracepoint is used to register a tracepoint with an EventMonitor.
// The tracepoint is selected by name and it must exist in the running Linux
// kernel. An event ID is returned that is unique to the EventMonitor and is
// to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterTracepoint(name string,
	fn TraceEventDecoderFn, options ...RegisterEventOption) (uint64, error) {

	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	eventid, err := monitor.newRegisteredEvent(name, fn, opts, eventTypeTracepoint)
	if err != nil {
		return 0, err
	}

	return eventid, nil
}

// RegisterKprobe is used to register a kprobe with an EventMonitor. The kprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unqiue to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterKprobe(address string, onReturn bool, output string,
	fn TraceEventDecoderFn, options ...RegisterEventOption) (uint64, error) {

	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addKprobe(name, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredEvent(name, fn, opts, eventTypeKprobe)
	if err != nil {
		monitor.removeKprobe(name)
		return 0, err
	}

	return eventid, nil
}

// RegisterUprobe is used to register a uprobe with an EventMonitor. The uprobe
// will first be registered with the kernel, and then registered with the
// EventMonitor. An event ID is returned that is unique to the EventMonitor and
// is to be used to unregister the event. The event ID will also be passed to
// the EventMonitor's dispatch function.
func (monitor *EventMonitor) RegisterUprobe(bin string, address string,
	onReturn bool, output string, fn TraceEventDecoderFn,
	options ...RegisterEventOption) (uint64, error) {

	opts := registerEventOptions{}
	for _, option := range options {
		option(&opts)
	}

	// If the address looks like a symbol that needs to be resolved, it
	// must be resolved here and now. The kernel does not do symbol
	// resolution for uprobes.
	if address[0] == '_' || unicode.IsLetter(rune(address[0])) {
		var err error
		address, err = monitor.resolveSymbol(bin, address)
		if err != nil {
			return 0, err
		}
	}

	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	name := monitor.newProbeName()
	err := monitor.addUprobe(name, bin, address, onReturn, output)
	if err != nil {
		return 0, err
	}

	eventid, err := monitor.newRegisteredEvent(name, fn, opts, eventTypeUprobe)
	if err != nil {
		monitor.removeUprobe(name)
		return 0, err
	}

	return eventid, nil
}

func baseAddress(file *elf.File, vaddr uint64) uint64 {
	if file.FileHeader.Type != elf.ET_EXEC {
		return 0
	}

	for _, prog := range file.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}

		if vaddr < prog.Vaddr || vaddr >= prog.Vaddr+prog.Memsz {
			continue
		}

		return prog.Vaddr
	}

	return 0
}

func symbolOffset(file *elf.File, name string, symbols []elf.Symbol) uint64 {
	for _, sym := range symbols {
		if sym.Name == name {
			return sym.Value - baseAddress(file, sym.Value)
		}
	}

	return 0
}

func (monitor *EventMonitor) resolveSymbol(bin, symbol string) (string, error) {
	file, err := elf.Open(bin)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// We don't know how to deal with anything other than ET_DYN or
	// ET_EXEC types.
	if file.FileHeader.Type != elf.ET_DYN && file.FileHeader.Type != elf.ET_EXEC {
		return "", fmt.Errorf("Executable is of unsupported ELF type %d",
			file.FileHeader.Type)
	}

	// Check symbols followed by dynamic symbols. Ignore errors from either
	// one, because they'll just be about the sections not existing, which
	// is fine. In the end, we'll generate our own error to return to the
	// caller if the symbol isn't found.

	var offset uint64
	symbols, _ := file.Symbols()
	offset = symbolOffset(file, symbol, symbols)
	if offset == 0 {
		symbols, _ = file.DynamicSymbols()
		offset = symbolOffset(file, symbol, symbols)
		if offset == 0 {
			return "", fmt.Errorf("Symbol %q not found in %q",
				symbol, bin)
		}
	}

	return fmt.Sprintf("%#x", offset), nil
}

// This should be called with monitor.lock held
func (monitor *EventMonitor) removeRegisteredEvent(event registeredEvent) {
	ids := make([]uint64, 0, len(event.fds))
	for _, fd := range event.fds {
		delete(monitor.eventfds, fd)
		id, ok := monitor.eventids[fd]
		if ok {
			ids = append(ids, id)
			delete(monitor.eventids, fd)
		}
		unix.Close(fd)
	}

	if monitor.isRunning {
		monitor.eventAttrMap.remove(ids)
		monitor.eventIDMap.remove(ids)
	} else {
		monitor.eventAttrMap.removeInPlace(ids)
		monitor.eventIDMap.removeInPlace(ids)
	}

	switch event.eventType {
	case eventTypeTracepoint:
		break
	case eventTypeKprobe:
		monitor.removeKprobe(event.name)
	case eventTypeUprobe:
		monitor.removeUprobe(event.name)
	}

	monitor.decoders.RemoveDecoder(event.name)
}

// UnregisterEvent is used to remove a previously registered event from an
// EventMonitor. The event can be of any type and is specified by the event
// ID that was returned when the event was initially registered with the
// EventMonitor.
func (monitor *EventMonitor) UnregisterEvent(eventid uint64) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events[eventid]
	if !ok {
		return errors.New("event is not registered")
	}
	delete(monitor.events, eventid)
	monitor.removeRegisteredEvent(event)

	return nil
}

// Close gracefully cleans up an EventMonitor instance. If the EventMonitor
// is still running when Close is called, it will first be stopped. After
// Close completes, the EventMonitor instance cannot be reused.
func (monitor *EventMonitor) Close(wait bool) error {
	// if the monitor is running, stop it and wait for it to stop
	monitor.Stop(wait)

	// This lock isn't strictly necessary -- by the time .Close() is
	// called, it would be a programming error for multiple go routines
	// to be trying to close the monitor or update events. It doesn't
	// hurt to lock, so do it anyway just to be on the safe side.
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	for _, event := range monitor.events {
		monitor.removeRegisteredEvent(event)
	}
	monitor.events = nil

	if len(monitor.eventfds) != 0 {
		panic("internal error: stray event fds left after monitor Close")
	}
	monitor.eventfds = nil

	if len(monitor.eventids) != 0 {
		panic("internal error: stray event ids left after monitor Close")
	}
	monitor.eventids = nil

	if len(monitor.eventAttrMap.getMap()) != 0 {
		panic("internal error: stray event attrs left after monitor Close")
	}
	monitor.eventAttrMap = nil

	if len(monitor.eventIDMap.getMap()) != 0 {
		panic("internal error: stray event IDs left after monitor Close")
	}
	monitor.eventIDMap = nil

	for _, group := range monitor.groups {
		group.cleanup()
	}
	monitor.groups = nil

	return nil
}

// Disable is used to disable a registered event. The event to disable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Disable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events[eventid]
	if ok {
		for _, fd := range event.fds {
			disable(fd)
		}
	}
}

// DisableAll disables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) DisableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		disable(fd)
	}
}

// Enable is used to enable a registered event. The event to enable is
// specified by its event ID as returned when the event was initially
// registered with the EventMonitor.
func (monitor *EventMonitor) Enable(eventid uint64) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events[eventid]
	if ok {
		for _, fd := range event.fds {
			enable(fd)
		}
	}
}

// EnableAll enables all events that are registered with the EventMonitor.
func (monitor *EventMonitor) EnableAll() {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	// Group FDs are always disabled
	for fd := range monitor.eventfds {
		enable(fd)
	}
}

// SetFilter is used to set or remove a filter from a registered event.
func (monitor *EventMonitor) SetFilter(eventid uint64, filter string) error {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	event, ok := monitor.events[eventid]
	if ok {
		for _, fd := range event.fds {
			err := setFilter(fd, filter)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (monitor *EventMonitor) stopWithSignal() {
	monitor.lock.Lock()
	monitor.isRunning = false
	monitor.cond.Broadcast()
	monitor.lock.Unlock()
}

type decodedSample struct {
	sample Sample
	err    error
}

type decodedSampleList []decodedSample

func (ds decodedSampleList) Len() int {
	return len(ds)
}

func (ds decodedSampleList) Swap(i, j int) {
	ds[i], ds[j] = ds[j], ds[i]
}

func (ds decodedSampleList) Less(i, j int) bool {
	return ds[i].sample.Time < ds[j].sample.Time
}

func (monitor *EventMonitor) dispatchSortedSamples(samples decodedSampleList) {
	dispatchFn := monitor.dispatchFn
	eventIDMap := monitor.eventIDMap.getMap()
	for _, ds := range samples {
		streamID := ds.sample.SampleID.StreamID
		eventID, ok := eventIDMap[streamID]
		if !ok {
			// Refresh the map in case we're dealing with a newly
			// added event, but more likely we're here because the
			// event has been removed while we're still processing
			// samples from the ringbuffer.
			eventIDMap = monitor.eventIDMap.getMap()
			eventID, ok = eventIDMap[streamID]
			if !ok {
				continue
			}
		}

		switch record := ds.sample.Record.(type) {
		case *SampleRecord:
			// Adjust the sample time so that it
			// matches the normalized timestamp.
			record.Time = ds.sample.Time
			s, err := monitor.decoders.DecodeSample(record)
			dispatchFn(eventID, s, err)
		default:
			dispatchFn(eventID, &ds.sample, ds.err)
		}
	}
}

func (monitor *EventMonitor) dispatchSamples() {
	defer monitor.wg.Done()

	for monitor.isRunning {
		select {
		case samples, ok := <-monitor.dispatchChan:
			if !ok {
				// Channel is closed; stop dispatch
				monitor.dispatchChan = nil

				// Signal completion of dispatch via WaitGroup
				return
			}

			// Sort the samples read from the ringbuffers
			sort.Sort(samples)

			// Dispatch the sorted samples
			monitor.dispatchSortedSamples(samples)
		}
	}
}

func (monitor *EventMonitor) readSamples(data []byte) {
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		ds := decodedSample{}
		ds.err = ds.sample.read(reader, nil, monitor.eventAttrMap.getMap())
		monitor.samples = append(monitor.samples, ds)
	}
}

func (monitor *EventMonitor) readRingBuffers(readyfds []int) {
	var (
		lastTimestamp uint64
		lastIndex     int
	)

	// Group fds are created with a read_format of 0, which means that the
	// data read from each fd will always be 8 bytes. We don't care about
	// the data, so we can safely ignore it. Due to the way that the
	// interface works, we don't have to read it as long as we empty the
	// associated ring buffer, which we will.

	for _, fd := range readyfds {
		// Read the samples from the ring buffer, and then normalize
		// the timestamps to be consistent across CPUs.
		first := len(monitor.samples)
		group := monitor.groups[fd]
		group.rb.read(monitor.readSamples)
		for i := first; i < len(monitor.samples); i++ {
			monitor.samples[i].sample.Time = group.timeBase +
				(monitor.samples[i].sample.Time - group.timeOffset)
		}

		if first == 0 {
			// Sometimes readyfds get no samples from the ringbuffer
			if len(monitor.samples) > 0 {
				lastTimestamp = monitor.samples[len(monitor.samples)-1].sample.Time
			}
		} else {
			x := len(monitor.samples)
			for i := x - 1; i > lastIndex; i-- {
				if monitor.samples[i].sample.Time > lastTimestamp {
					x--
				}
			}
			if x != len(monitor.samples) {
				monitor.pendingSamples = append(monitor.pendingSamples, monitor.samples[x:]...)
				monitor.samples = monitor.samples[:x]
			}
		}
		lastIndex = len(monitor.samples)
	}

	if len(monitor.samples) > 0 {
		if len(monitor.pendingSamples) > 0 {
			monitor.samples = append(monitor.samples, monitor.pendingSamples...)
			monitor.pendingSamples = monitor.pendingSamples[:0]
		}
		monitor.dispatchChan <- monitor.samples
		monitor.samples = nil
	}
}

func (monitor *EventMonitor) flushPendingSamples() {
	if len(monitor.pendingSamples) > 0 {
		monitor.dispatchChan <- monitor.pendingSamples
		monitor.pendingSamples = nil
	}
}

func addPollFd(pollfds []unix.PollFd, fd int) []unix.PollFd {
	pollfd := unix.PollFd{
		Fd:     int32(fd),
		Events: unix.POLLIN,
	}
	return append(pollfds, pollfd)
}

// Run puts an EventMonitor into the running state. While an EventMonitor is
// running, samples will be pulled from event sources, decoded, and dispatched
// to a function that is specified here.
func (monitor *EventMonitor) Run(fn SampleDispatchFn) error {
	monitor.lock.Lock()
	if monitor.isRunning {
		monitor.lock.Unlock()
		return errors.New("monitor is already running")
	}
	monitor.isRunning = true

	err := unix.Pipe(monitor.pipe[:])
	monitor.lock.Unlock()
	if err != nil {
		monitor.stopWithSignal()
		return err
	}

	monitor.dispatchChan = make(chan decodedSampleList,
		config.Sensor.ChannelBufferLength)
	monitor.dispatchFn = fn

	monitor.wg.Add(1)
	go monitor.dispatchSamples()

	// Set up the fds for polling. Monitor only the groupfds, because they
	// will encapsulate all of the eventfds and they're tied to the ring
	// buffers.
	pollfds := make([]unix.PollFd, 0, len(monitor.groups)+1)
	pollfds = addPollFd(pollfds, monitor.pipe[0])
	for fd := range monitor.groups {
		pollfds = addPollFd(pollfds, fd)
	}

runloop:
	for {
		var n int

		// If there are pending samples, check for waiting events and
		// return immediately. If there aren't any, flush everything
		// pending and go back to waiting for events normally. If there
		// are events, the pending events will get handled during
		// normal processing
		if len(monitor.pendingSamples) > 0 {
			n, err = unix.Poll(pollfds, 0)
			if err != nil && err != unix.EINTR {
				break
			}
			if n == 0 {
				monitor.flushPendingSamples()
				continue
			}
		} else {
			n, err = unix.Poll(pollfds, -1)
			if err != nil && err != unix.EINTR {
				break
			}
		}

		if n > 0 {
			readyfds := make([]int, 0, n)
			for i, fd := range pollfds {
				if i == 0 {
					if (fd.Revents & ^unix.POLLIN) != 0 {
						// POLLERR, POLLHUP, or POLLNVAL set
						break runloop
					}
				} else if (fd.Revents & unix.POLLIN) != 0 {
					readyfds = append(readyfds, int(fd.Fd))
				}
			}
			if len(readyfds) > 0 {
				monitor.readRingBuffers(readyfds)
			} else if len(monitor.pendingSamples) > 0 {
				monitor.flushPendingSamples()
			}
		}
	}

	if monitor.dispatchChan != nil {
		close(monitor.dispatchChan)
	}

	monitor.lock.Lock()
	if monitor.pipe[1] != -1 {
		unix.Close(monitor.pipe[1])
		monitor.pipe[1] = -1
	}
	if monitor.pipe[0] != -1 {
		unix.Close(monitor.pipe[0])
		monitor.pipe[0] = -1
	}
	monitor.lock.Unlock()

	if monitor.dispatchChan != nil {
		// Wait for dispatchSamples goroutine to exit
		monitor.wg.Wait()
	}

	monitor.stopWithSignal()
	return err
}

// Stop stops a running EventMonitor. If the EventMonitor is not running, this
// function does nothing. Once an EventMonitor has been stopped, it may be
// restarted again. Whether Stop waits for the EventMonitor to fully stop is
// optional, but if the caller does not wait there is no other mechanism by
// which the caller may learn whether the EventMonitor is stopped.
func (monitor *EventMonitor) Stop(wait bool) {
	monitor.lock.Lock()
	defer monitor.lock.Unlock()

	if !monitor.isRunning {
		return
	}

	if monitor.pipe[1] != -1 {
		fd := monitor.pipe[1]
		monitor.pipe[1] = -1
		unix.Close(fd)
	}

	if wait {
		for monitor.isRunning {
			// Wait for condition to signal that Run() is done
			monitor.cond.Wait()
		}
	}
}

var referenceEventAttr = EventAttr{
	Type:         PERF_TYPE_SOFTWARE,
	Size:         sizeofPerfEventAttr,
	Config:       PERF_COUNT_SW_CONTEXT_SWITCHES,
	SampleFreq:   1,
	SampleType:   PERF_SAMPLE_TIME,
	Freq:         true,
	WakeupEvents: 1,
}

func (monitor *EventMonitor) readReferenceSamples(data []byte) {
	reader := bytes.NewReader(data)
	for reader.Len() > 0 {
		ds := decodedSample{}
		ds.err = ds.sample.read(reader, &referenceEventAttr, nil)
		monitor.samples = append(monitor.samples, ds)
	}
}

func (monitor *EventMonitor) cpuTimeOffset(cpu int, groupfd int, rb *ringBuffer) (uint64, error) {
	// Create a temporary event to get a reference timestamp. What
	// type of event we use is unimportant. We just want something
	// that will be reported immediately. After the timestamp is
	// retrieved, we can get rid of it.
	fd, err := open(&referenceEventAttr, -1, cpu, groupfd,
		(PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP))
	if err != nil {
		glog.V(3).Infof("Couldn't open reference event: %s", err)
		return 0, err
	}

	// Wait for the event to be ready, then pull it immediately and
	// remember the timestamp. That's our reference for this CPU.
	pollfds := []unix.PollFd{
		unix.PollFd{
			Fd:     int32(groupfd),
			Events: unix.POLLIN,
		},
	}
	for {
		n, err := unix.Poll(pollfds, -1)
		if err != nil && err != unix.EINTR {
			unix.Close(fd)
			return 0, err
		}
		if n == 0 {
			continue
		}

		rb.read(monitor.readReferenceSamples)
		if len(monitor.samples) == 0 {
			continue
		}
		ds := monitor.samples[0]

		// Close the event to prevent any more samples from being
		// added to the ring buffer. Remove anything from the ring
		// buffer that remains and discard it.
		unix.Close(fd)
		rb.read(monitor.readReferenceSamples)
		monitor.samples = nil

		if ds.err != nil {
			return 0, err
		}

		return ds.sample.Time - rb.timeRunning(), nil
	}
}

func (monitor *EventMonitor) initializeGroupLeaders(pid int, flags uintptr, ringBufferNumPages int) error {
	groupEventAttr := &EventAttr{
		Type:            PERF_TYPE_SOFTWARE,
		Size:            sizeofPerfEventAttr,
		Config:          PERF_COUNT_SW_DUMMY, // Added in Linux 3.12
		Disabled:        true,
		Watermark:       true,
		WakeupWatermark: 1,
	}

	ncpu := runtime.NumCPU()
	newfds := make(map[int]perfEventGroup, ncpu)

	for cpu := 0; cpu < ncpu; cpu++ {
		groupfd, err := open(groupEventAttr, pid, cpu, -1, flags)
		if err != nil {
			for fd := range newfds {
				unix.Close(fd)
			}
			return err
		}

		newGroup := perfEventGroup{
			pid:   pid,
			cpu:   cpu,
			fd:    groupfd,
			flags: flags,
		}

		rb, err := newRingBuffer(groupfd, ringBufferNumPages)
		if err == nil {
			var offset uint64

			newGroup.rb = rb

			offset, err = monitor.cpuTimeOffset(cpu, groupfd, rb)
			if err == nil {
				newGroup.timeBase = uint64(time.Now().UnixNano())
				newGroup.timeOffset = offset
				newfds[groupfd] = newGroup
				continue
			}
		}

		// This is the common error case
		newGroup.cleanup()
		for _, group := range newfds {
			group.cleanup()
		}
		return err
	}

	for k, v := range newfds {
		monitor.groups[k] = v
	}

	return nil
}

func doProbeCleanup(tracingDir, eventsFile string, activePids, deadPids map[int]bool) {
	eventsFilename := filepath.Join(tracingDir, eventsFile)
	data, err := ioutil.ReadFile(eventsFilename)
	if err != nil {
		return
	}

	var file *os.File

	// Read one line at a time and check for capsule8/sensor_ probes. The
	// pid that created the probe is encoded within. If the pid is dead,
	// remove the probe.
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		name := line[2:strings.Index(line, " ")]
		if !strings.HasPrefix(name, "capsule8/sensor_") {
			continue
		}

		// Capsule8 sensor names are of the form sensor_<pid>_<count>
		var pid int
		fmt.Sscanf(name, "capsule8/sensor_%d_", &pid)
		if activePids[pid] {
			continue
		} else if !deadPids[pid] {
			if syscall.Kill(pid, 0) != syscall.ESRCH {
				activePids[pid] = true
				continue
			}
			deadPids[pid] = true
		}

		cmd := fmt.Sprintf("-:%s\n", name)
		if file == nil {
			file, err = os.OpenFile(eventsFilename, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				glog.Errorf("Couldn't open %s WO+A: %s", eventsFilename, err)
				return
			}
			defer file.Close()
		}
		file.Write([]byte(cmd))
		glog.V(1).Infof("Removed stale probe from %s: %s", eventsFile, name)
	}
}

func cleanupStaleProbes(tracingDir string) {
	activePids := make(map[int]bool)
	deadPids := make(map[int]bool)

	activePids[os.Getpid()] = true

	doProbeCleanup(tracingDir, "kprobe_events", activePids, deadPids)
	doProbeCleanup(tracingDir, "uprobe_events", activePids, deadPids)
}

// NewEventMonitor creates a new EventMonitor instance in the stopped state.
// Once an EventMonitor instance is returned from this function, its Close
// method must be called to clean it up gracefully, even if no events are
// registered or it is never put into the running state.
func NewEventMonitor(options ...EventMonitorOption) (*EventMonitor, error) {
	// Process options
	opts := eventMonitorOptions{}
	for _, option := range options {
		option(&opts)
	}

	var eventAttr EventAttr

	if opts.defaultEventAttr == nil {
		eventAttr = EventAttr{
			SampleType:  PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
			Inherit:     true,
			SampleIDAll: true,
		}
	} else {
		eventAttr = *opts.defaultEventAttr
	}
	fixupEventAttr(&eventAttr)

	// Only allow certain flags to be passed
	opts.flags &= PERF_FLAG_FD_CLOEXEC

	// If no tracing dir was specified, scan mounts for one
	if len(opts.tracingDir) == 0 {
		opts.tracingDir = sys.TracingDir()
	}
	cleanupStaleProbes(opts.tracingDir)

	// If no perf_event cgroup mountpoint was specified, scan mounts for one
	if len(opts.perfEventDir) == 0 && len(opts.cgroups) > 0 {
		opts.perfEventDir = sys.PerfEventDir()

		// If we didn't find one, we can't monitor specific cgroups
		if len(opts.perfEventDir) == 0 {
			return nil, errors.New("Can't monitor specific cgroups without perf_event cgroupfs")
		}
	}

	// If no pids or cgroups were specified, default to monitoring the
	// whole system (pid -1)
	if len(opts.pids) == 0 && len(opts.cgroups) == 0 {
		opts.pids = append(opts.pids, -1)
	}

	monitor := &EventMonitor{
		groups:       make(map[int]perfEventGroup),
		eventAttrMap: newSafeEventAttrMap(),
		eventIDMap:   newSafeUInt64Map(),
		decoders:     newTraceEventDecoderMap(opts.tracingDir),
		nextEventID:  1,
		events:       make(map[uint64]registeredEvent),
		eventfds:     make(map[int]int),
		eventids:     make(map[int]uint64),
		defaultAttr:  eventAttr,
		tracingDir:   opts.tracingDir,
	}
	monitor.lock = &sync.Mutex{}
	monitor.cond = sync.NewCond(monitor.lock)

	cgroups := make(map[string]bool, len(opts.cgroups))
	for _, cgroup := range opts.cgroups {
		if cgroups[cgroup] {
			glog.V(1).Infof("Ignoring duplicate cgroup %s", cgroup)
			continue
		}
		cgroups[cgroup] = true

		path := filepath.Join(opts.perfEventDir, cgroup)
		fd, err := unix.Open(path, unix.O_RDONLY, 0)
		if err == nil {
			err = monitor.initializeGroupLeaders(fd,
				opts.flags|PERF_FLAG_PID_CGROUP,
				opts.ringBufferNumPages)
			if err == nil {
				continue
			}
		}

		for _, group := range monitor.groups {
			group.cleanup()
		}
		return nil, err
	}

	pids := make(map[int]bool, len(opts.pids))
	for _, pid := range opts.pids {
		if pids[pid] {
			glog.V(1).Infof("Ignoring duplicate pid %d", pid)
			continue
		}
		pids[pid] = true

		err := monitor.initializeGroupLeaders(pid, opts.flags,
			opts.ringBufferNumPages)
		if err == nil {
			continue
		}

		for _, group := range monitor.groups {
			group.cleanup()
		}
		return nil, err
	}

	return monitor, nil
}
