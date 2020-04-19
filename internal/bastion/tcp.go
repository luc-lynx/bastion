package bastion

import (
	"fmt"
	"net"

	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type tcpConfig struct {
	dstHost string
	dstPort uint16
	server  *Server
	channel ssh.NewChannel
}

func NewTCPConnectionHandler(channel ssh.NewChannel, server *Server, dstHost string, dstPort uint16) (*tcpConfig, error) {
	return &tcpConfig{
		dstHost: dstHost,
		dstPort: dstPort,
		server: server,
		channel: channel,
	}, nil
}

func (t *tcpConfig) Run() {
	if t.server.client == nil {
		t.server.errorsChannel <- t.channel.Reject(ssh.ConnectionFailed, "there's no connection active connection open")
	}

	t.server.Info("dialing tcp", "host", t.dstHost, "port", t.dstPort)
	conn, err := t.server.client.Dial("tcp", fmt.Sprintf("%s:%d", t.dstHost, t.dstPort))
	if err != nil {
		t.server.errorsChannel <- errors.Wrap(err, "couldn't dial")
		t.server.errorsChannel <- t.channel.Reject(ssh.ConnectionFailed, "couldn't connect to a remote host")
		return
	}
	defer conn.Close()

	channel, requests, err := t.channel.Accept()
	if err != nil {
		t.server.errorsChannel <- errors.Wrap(err, "failed to accept channel")
		return
	}
	t.server.Info("channel accepted")
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	tcpLog := logger.TCPLogger{
		Logger: logger.Logger{
			ClientIn:   channel,
			ClientOut:  channel,
			ServerIn:   conn,
			ServerOut:  conn,
			Username:   t.server.remoteUser,
			Hostname:   t.dstHost,
			SessId:     t.server.sessionID,
			RootFolder: t.server.Conf.LogFolder,
		},
		// TODO
		Src:     net.IP{127, 0, 0, 1},
		Dst:     net.IP{1, 1, 1, 1},
		SrcPort: 22,
		DstPort: t.dstPort,
	}

	if err := tcpLog.Start(); err != nil {
		t.server.Errorw("error writing tcp log", "err", err)
	}
}
