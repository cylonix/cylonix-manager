package common

import (
	"context"
	"os"
	"os/signal"
	"sync"

	"cylonix/sase/pkg/lock"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/pidfile"

	"github.com/google/gops/agent"
	"github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

var cleaner *Cleaner

func StartCleaner(logger *logrus.Entry) *Cleaner {
 	cleaner = &Cleaner{
		cleanUPSig:   make(chan struct{}),
		cleanUPWg:    &sync.WaitGroup{},
		cleanupFuncs: &cleanupFuncList{
			funcs: make([]cleanupFunc, 0),
		},
		logger: logger.WithField(logfields.LogSubsys, "cleaner"),
	}
	return cleaner
}

type Cleaner struct {
	lock.Mutex

	// CleanUPSig channel is closed when the daemon is to be terminated.
	cleanUPSig chan struct{}

	// All cleanup operations will be marked as Done() when completed.
	cleanUPWg *sync.WaitGroup

	cleanupFuncs *cleanupFuncList

	sigHandlerCancel context.CancelFunc

	logger *logrus.Entry
}

type cleanupFunc struct {
	handler func()
	name    string
}
type cleanupFuncList struct {
	funcs []cleanupFunc
	lock  lock.Mutex
}

func (c *cleanupFuncList) add(name string, newFunc func()) {
	c.lock.Lock()
	c.funcs = append(c.funcs, cleanupFunc{
		name:    name,
		handler: newFunc,
	})
	c.lock.Unlock()
}

func (c *cleanupFuncList) Run() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k := range c.funcs {
		cleaner.logger.WithField("name", c.funcs[k].name).Infoln("Cleanup resources...")
		c.funcs[k].handler()
	}
}

func (d *Cleaner) RegisterSigHandler() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGQUIT, unix.SIGINT, unix.SIGHUP, unix.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		s := <- sig
		cleaner.logger.WithField("signal", s).Infoln("Exiting due to signal")
		d.Lock()
		if d.sigHandlerCancel != nil {
			d.sigHandlerCancel()
		}
		d.Unlock()
		pidfile.Clean()
		d.Clean()
		d.cleanupFuncs.Run()
		close(interrupt)
	}()
	return interrupt
}

func (d *Cleaner) AddCleanUpFunc(name string, newFunc func()) {
	d.cleanupFuncs.add(name, newFunc)
}

// Clean cleans up everything created by this package.
func (d *Cleaner) Clean() {
	agent.Close()
	close(d.cleanUPSig)
	d.cleanUPWg.Wait()
}

// SetCancelFunc sets the function which is called when we receive a signal to
// propagate cancellation down to ongoing operations. If it's already set,
// it does nothing.
func (d *Cleaner) SetCancelFunc(cancelFunc context.CancelFunc) {
	d.Lock()
	defer d.Unlock()
	if d.sigHandlerCancel != nil {
		return
	}
	d.sigHandlerCancel = cancelFunc
}
