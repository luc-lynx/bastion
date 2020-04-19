package bastion

import (
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func RunStandalone(c Config, log *zap.SugaredLogger) error {
	sock, err := net.Listen("tcp", fmt.Sprintf(":%d", c.StandalonePort))
	if err != nil {
		return err
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			log.Errorf("failed to accept connection: %s", err.Error())
		}

		log.Debugf("accepted connection")

		go func(cn net.Conn, logger *zap.SugaredLogger) {
			defer cn.Close()
			s := NewServer(c, logger)
			if err := s.ProcessConnection(cn); err != nil {
				log.Errorw("failed to process connection", "err", err)
				return
			}
		}(conn, log)
	}
}

func Run(conf Config, log *zap.SugaredLogger) (err error) {
	var clientConn net.Conn
	if conf.InetDStyle {
		clientConn = stdioNetConn{}
	} else {
		clientConn, err = net.FileConn(os.NewFile(3, "nConn"))
		for err != nil {
			return errors.Wrap(err, "failed to create client conn")
		}
		defer clientConn.Close()
	}

	server := NewServer(conf, log)
	if err = server.ProcessConnection(clientConn); err != nil {
		log.Errorw("error while handling connection", "err", err)
		return
	}
	return
}
