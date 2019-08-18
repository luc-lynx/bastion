package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

type SessionLogger struct {
	Logger

	ClientErr io.Writer
	ServerErr io.Reader
	PTY       bool
	PTYCols   uint32
	PTYRows   uint32
	Command   string

	timer *Timer
}

type Timer struct {
	time.Time
	sync.Mutex
}

func (t *Timer) Init() {
	t.Time = time.Now()
}

func (t *Timer) GetDiff() time.Duration {
	t.Lock()
	defer t.Unlock()

	now := time.Now()
	diff := now.Sub(t.Time)
	t.Time = now
	return diff
}

type TimingWriter struct {
	log    io.WriteCloser
	timing io.WriteCloser
	id     int
	timer  *Timer
}

func (tw TimingWriter) Write(p []byte) (n int, err error) {
	n, err = tw.log.Write(p)
	if err != nil {
		return
	}
	secDiff := float64(tw.timer.GetDiff()) / float64(time.Second)
	te := fmt.Sprintf("%d %.6f %d\n", tw.id, secDiff, n)
	// TODO: check err
	tw.timing.Write([]byte(te))
	return
}

func (tw TimingWriter) Close() error {
	// TODO
	tw.timing.Close()
	return tw.log.Close()
}

func (sl *SessionLogger) createFiles() (res []io.WriteCloser, timing io.WriteCloser, err error) {
	timing, err = os.Create(path.Join(sl.folder(), "timing"))
	if err != nil {
		return
	}

	for id, fname := range []string{"stdin", "stdout", "stderr", "ttyin", "ttyout"} {
		log, err := os.Create(path.Join(sl.folder(), fname))
		if err != nil {
			return res, timing, err
		}
		tw := TimingWriter{
			log:    log,
			timing: timing,
			id:     id,
			timer:  sl.timer,
		}
		res = append(res, tw)
	}
	return
}

func (sl *SessionLogger) Start() (err error) {
	sl.timer = &Timer{}
	sl.timer.Init()

	os.MkdirAll(sl.folder(), 0700)

	if sl.Command == "" {
		sl.Command = "/SHELL"
	}
	logData := fmt.Sprintf("%d:%s:::/dev/pts/0:%d:%d\n/\n%s",
		sl.timer.Time.Unix(), sl.Username, sl.PTYRows, sl.PTYCols, sl.Command)
	err = ioutil.WriteFile(path.Join(sl.folder(), "log"), []byte(logData), 0600)
	if err != nil {
		return
	}

	logs, timing, err := sl.createFiles()
	if err != nil {
		// TODO: close if partial success
		return
	}
	defer timing.Close()
	for _, log := range logs {
		defer log.Close()
	}

	errs := make(chan error)
	if !sl.PTY {
		sl.startLog(sl.ClientIn, sl.ServerIn, logs[0], errs)
		sl.startLog(sl.ServerOut, sl.ClientOut, logs[1], errs)
		sl.startLog(sl.ServerErr, sl.ClientErr, logs[2], errs)
	} else {
		sl.startLog(sl.ClientIn, sl.ServerIn, logs[3], errs)
		sl.startLog(sl.ServerOut, sl.ClientOut, logs[4], errs)
	}

	// TODO: handle errors
	<-errs
	<-errs
	if !sl.PTY {
		<-errs
	}

	return nil
}
