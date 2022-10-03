// Copyright (c) 2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package tally

import (
	"hash/maphash"
	"runtime"
	"sync"
	"unsafe"
)

var scopeRegistryKey = keyForPrefixedStringMaps

type scopeRegistry struct {
	seed      maphash.Seed
	root      *scope
	subscopes []*bucketScope
}

type bucketScope struct {
	sync.RWMutex
	s map[string]*scope
}

func newScopeRegistry(root *scope) *scopeRegistry {
	procs := runtime.GOMAXPROCS(-1)

	r := &scopeRegistry{
		root:      root,
		subscopes: make([]*bucketScope, procs),
		seed:      maphash.MakeSeed(),
	}

	for i := 0; i < procs; i++ {
		r.subscopes[i] = &bucketScope{
			s: make(map[string]*scope),
		}
		r.subscopes[i].s[scopeRegistryKey(root.prefix, root.tags)] = root
	}

	return r
}

func (r *scopeRegistry) Report(reporter StatsReporter) {
	defer r.purgeIfRootClosed()

	for _, ptr := range r.subscopes {
		ptr.RLock()

		for name, s := range ptr.s {
			s.report(reporter)

			if s.closed.Load() {
				r.removeWithRLock(ptr, name)
				s.clearMetrics()
			}
		}

		ptr.RUnlock()
	}
}

func (r *scopeRegistry) CachedReport() {
	defer r.purgeIfRootClosed()

	for _, ptr := range r.subscopes {
		ptr.RLock()

		for name, s := range ptr.s {
			s.cachedReport()

			if s.closed.Load() {
				r.removeWithRLock(ptr, name)
				s.clearMetrics()
			}
		}

		ptr.RUnlock()
	}
}

func (r *scopeRegistry) ForEachScope(f func(*scope)) {
	for _, ptr := range r.subscopes {
		for _, s := range ptr.s {
			ptr.RLock()
			f(s)
			ptr.RUnlock()
		}
	}
}

func (r *scopeRegistry) Subscope(parent *scope, prefix string, tags map[string]string) *scope {
	if r.root.closed.Load() || parent.closed.Load() {
		return NoopScope.(*scope)
	}

	buf := keyForPrefixedStringMapsAsKey(make([]byte, 0, 256), prefix, parent.tags, tags)
	h := maphash.Hash{}
	h.SetSeed(r.seed)
	_, _ = h.Write(buf)
	ptr := r.subscopes[h.Sum64()%uint64(len(r.subscopes))]

	ptr.RLock()
	// buf is stack allocated and casting it to a string for lookup from the cache
	// as the memory layout of []byte is a superset of string the below casting is safe and does not do any alloc
	// However it cannot be used outside of the stack; a heap allocation is needed if that string needs to be stored
	// in the map as a key
	if s, ok := r.lockedLookup(ptr, *(*string)(unsafe.Pointer(&buf))); ok {
		ptr.RUnlock()
		return s
	}
	ptr.RUnlock()

	// heap allocating the buf as a string to keep the key in the subscopes map
	preSanitizeKey := string(buf)
	tags = parent.copyAndSanitizeMap(tags)
	key := scopeRegistryKey(prefix, parent.tags, tags)

	ptr.Lock()
	defer ptr.Unlock()

	if s, ok := r.lockedLookup(ptr, key); ok {
		if _, ok = r.lockedLookup(ptr, preSanitizeKey); !ok {
			ptr.s[preSanitizeKey] = s
		}
		return s
	}

	allTags := mergeRightTags(parent.tags, tags)
	subscope := &scope{
		separator: parent.separator,
		prefix:    prefix,
		// NB(prateek): don't need to copy the tags here,
		// we assume the map provided is immutable.
		tags:           allTags,
		reporter:       parent.reporter,
		cachedReporter: parent.cachedReporter,
		baseReporter:   parent.baseReporter,
		defaultBuckets: parent.defaultBuckets,
		sanitizer:      parent.sanitizer,
		registry:       parent.registry,

		counters:        make(map[string]*counter),
		countersSlice:   make([]*counter, 0, _defaultInitialSliceSize),
		gauges:          make(map[string]*gauge),
		gaugesSlice:     make([]*gauge, 0, _defaultInitialSliceSize),
		histograms:      make(map[string]*histogram),
		histogramsSlice: make([]*histogram, 0, _defaultInitialSliceSize),
		timers:          make(map[string]*timer),
		bucketCache:     parent.bucketCache,
		done:            make(chan struct{}),
	}
	ptr.s[key] = subscope
	if _, ok := r.lockedLookup(ptr, preSanitizeKey); !ok {
		ptr.s[preSanitizeKey] = subscope
	}
	return subscope
}

func (r *scopeRegistry) lockedLookup(ptr *bucketScope, key string) (*scope, bool) {
	ss, ok := ptr.s[key]
	return ss, ok
}

func (r *scopeRegistry) purgeIfRootClosed() {
	if !r.root.closed.Load() {
		return
	}

	for _, ptr := range r.subscopes {
		for k, s := range ptr.s {
			_ = s.Close()
			s.clearMetrics()
			delete(ptr.s, k)
		}
	}
}

func (r *scopeRegistry) removeWithRLock(ptr *bucketScope, key string) {
	// n.b. This function must lock the registry for writing and return it to an
	//      RLocked state prior to exiting. Defer order is important (LIFO).
	ptr.RUnlock()
	defer ptr.RLock()
	ptr.Lock()
	defer ptr.Unlock()
	delete(ptr.s, key)
}
