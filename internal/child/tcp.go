package child

import (
	"fmt"
	"net"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/logger"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type tcpConfig struct {
	channelConfig
	dstHost string
	dstPort uint16
}

func HandleTCP(ch ssh.NewChannel, tc *tcpConfig) {
	// TODO: ACL
	// TODO: validate host

	tc.Info("getting ssh client")
	c, err := tc.clientProv.GetClient(&client.Config{
		User:    tc.username,
		Host:    tc.dstHost,
		Port:    22,
		Agent:   tc.agent,
		Timeout: tc.conf.ConnectTimeout,
		Log:     tc.SugaredLogger,
	})
	if err != nil {
		tc.errs <- errors.Wrap(err, "failed to create client")
		return
	}
	defer c.Close()

	tc.Info("dialing tcp")
	conn, err := c.Dial("tcp", fmt.Sprintf("%s:%d", tc.dstHost, tc.dstPort))
	if err != nil {
		ch.Reject(ssh.ConnectionFailed, "")
		c.Warnw("failed to dial tcp", "err", err)
		return
	}
	defer conn.Close()

	tc.Info("accepting request")
	channel, reqs, err := ch.Accept()
	if err != nil {
		tc.errs <- errors.Wrap(err, "failed to accept channel")
		return
	}
	tc.Info("accepted tcp channel")
	go ssh.DiscardRequests(reqs)

	defer channel.Close()

	log := logger.TCPLogger{
		Logger: logger.Logger{
			ClientIn:   channel,
			ClientOut:  channel,
			ServerIn:   conn,
			ServerOut:  conn,
			Username:   tc.username,
			Hostname:   tc.dstHost,
			SessId:     tc.sessId,
			RootFolder: tc.conf.LogFolder,
		},
		// TODO
		Src:     net.IP{127, 0, 0, 1},
		Dst:     net.IP{8, 8, 8, 8},
		SrcPort: 1337,
		DstPort: 7331,
	}
	log.Start()
}