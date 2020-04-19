package bastion

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/ilyaluk/bastion/internal/client"
	"github.com/ilyaluk/bastion/internal/ssh_types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const (
	DefaultSSHPort = 22
	SSHServerVersion = "SSH-2.0-OpenSSH_Go_Bastion"
	OldBastionPrefix = "/tmp/.fwd/localhost/"
	Localhost = "127.0.0.1"
)

// Server implements SSH server that client connects to
type Server struct {
	Conf Config
	*zap.SugaredLogger
	acl *ACLValidator

	sshConn     *ssh.ServerConn
	sessId      []byte
	remoteUser  string
	remoteHost  string
	remotePort  uint16
	agent       *ClientAgent
	certChecker *ssh.CertChecker
	errs        chan error

	client         *client.Client
	noMoreSessions bool
}

func NewServer(conf Config, log *zap.SugaredLogger) *Server {
	return &Server{
		Conf:          conf,
		SugaredLogger: log,
		acl:           NewACLValidator(conf.ACL),
	}
}

func (s *Server) authCallback(sc ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	username := sc.User()
	s.Infow("auth_callback for user", "user", username)
	username = strings.Split(username, "/")[0]
	meta := customSSHConnMetadata{
		ConnMetadata: sc,
		customUser:   username,
	}
	keyFp := ssh.FingerprintSHA256(pubKey)

	clientCert, ok := pubKey.(*ssh.Certificate)
	if s.certChecker != nil && ok {
		// client offered signed certificate and we have certChecker
		certFp := ssh.FingerprintSHA256(clientCert.SignatureKey)
		perms, err := s.certChecker.Authenticate(meta, pubKey)
		if err != nil {
			s.Infow("client offered invalid certificate",
				"err", err,
				"user", username,
				"pubkey-fp", keyFp,
				"ca-fp", certFp,
				"sessid", sc.SessionID(),
			)
			return nil, err
		}
		s.Infow("client offered valid certificate",
			"user", username,
			"pubkey-fp", keyFp,
			"ca-fp", certFp,
			"sessid", sc.SessionID(),
		)
		return perms, nil
	}

	if s.Conf.AllowOnlyCertificates {
		return nil, errors.New("only certificates allowed")
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return nil, errors.Wrap(err, "cannot lookup user")
	}
	if usr.HomeDir == "" {
		return nil, errors.New("user have no homedir")
	}
	ak, err := readAuthorizedKeys(fmt.Sprintf("%s/.ssh/authorized_keys", usr.HomeDir))
	if err != nil {
		return nil, errors.Wrap(err, "cannot read authorized_keys")
	}

	if ak[string(pubKey.Marshal())] {
		s.Infow("client offered valid key",
			"user", username,
			"pubkey-fp", keyFp,
			"sessid", sc.SessionID(),
		)
		return &ssh.Permissions{}, nil
	}
	s.Infow("client offered invalid key",
		"user", username,
		"pubkey-fp", keyFp,
		"sessid", sc.SessionID(),
	)
	return nil, fmt.Errorf("unknown public key for %q", sc.User())
}

func handleProxyJump(remoteHost string, port uint16, logger *zap.SugaredLogger, cnf Config, ch ssh.NewChannel) error {
	innerServer := NewServer(cnf, logger)
	innerServer.remoteHost = remoteHost
	innerServer.remotePort = port

	channel, reqs, err := ch.Accept()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to accept ssh channel for %s:%d", remoteHost, port))
	}

	go ssh.DiscardRequests(reqs)
	return innerServer.ProcessConnection(fakeNetConn{channel})
}

func readStreamlocalParams(channel ssh.NewChannel) (*ssh_types.ChannelOpenDirectMsg, error) {
	var udsForwardRequest ssh_types.ChannelOpenDirectUDSMsg
	if err := ssh.Unmarshal(channel.ExtraData(), &udsForwardRequest); err != nil {
		return nil, errors.Wrap(err, "error parsing uds request")
	}

	if strings.Index(udsForwardRequest.RAddr, OldBastionPrefix) == 0 {
		var result ssh_types.ChannelOpenDirectMsg
		result.LAddr = udsForwardRequest.LAddr
		result.LPort = udsForwardRequest.LPort
		result.RAddr = Localhost
		port, err := strconv.Atoi(udsForwardRequest.RAddr[len(OldBastionPrefix):])
		if err != nil {
			return nil, errors.Wrap(err, "invalid port number in forward request")
		}
		result.RPort = uint32(port)
		return &result, nil
	} else {
		return nil, errors.New("unix domain sockets are't supported")
	}
}

func readDirectTcpParams(channel ssh.NewChannel) (*ssh_types.ChannelOpenDirectMsg, error) {
	var result ssh_types.ChannelOpenDirectMsg
	err := ssh.Unmarshal(channel.ExtraData(), &result)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing direct tcp-ip request")
	}

	return &result, nil
}

func (s *Server) processClient(sshChans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	for {
		if sshChans == nil && reqs == nil {
			break
		}

		select {
		case ch, ok := <-sshChans:
			if !ok {
				sshChans = nil
				continue
			}
			s.Debugw("new channel request", "type", ch.ChannelType())

			switch ch.ChannelType() {
			case "session":
				if s.noMoreSessions {
					s.errs <- ch.Reject(ssh.Prohibited, "no-more-sessions was sent")
					continue
				}
				s.Infow("session request")

				go HandleSession(&sessionConfig{
					newCh: ch,
					serv:  s,
				})

			case "direct-tcpip", "direct-streamlocal@openssh.com":
				var tcpForwardReq ssh_types.ChannelOpenDirectMsg
				if ch.ChannelType() == "direct-streamlocal@openssh.com" {
					params, err := readStreamlocalParams(ch)
					if err != nil {
						s.errs <- ch.Reject(ssh.Prohibited, err.Error())
						continue
					}
					tcpForwardReq = *params
				} else {
					params, err := readDirectTcpParams(ch)
					if err != nil {
						s.errs <- err
						continue
					}
					tcpForwardReq = *params
				}

				s.Infow("tcpip request", "req", tcpForwardReq)

				if s.client == nil && tcpForwardReq.LPort == 65535 && tcpForwardReq.LAddr == "127.0.0.1" {
					s.Info("OpenSSH connects with -J")
					s.errs <- handleProxyJump(tcpForwardReq.RAddr, uint16(tcpForwardReq.RPort), s.SugaredLogger, s.Conf, ch)
					return
				}

				if !s.acl.CheckForward(s.remoteUser, tcpForwardReq.RAddr, uint16(tcpForwardReq.RPort)) {
					s.Warnw("access denied")
					s.errs <- ch.Reject(ssh.Prohibited, "access denied")
					continue
				}

				go HandleTCP(&tcpConfig{
					newCh:   ch,
					serv:    s,
					srcHost: tcpForwardReq.LAddr,
					srcPort: uint16(tcpForwardReq.LPort),
					dstHost: tcpForwardReq.RAddr,
					dstPort: uint16(tcpForwardReq.RPort),
				})

			case "x11", "forwarded-tcpip", "tun@openssh.com", "forwarded-streamlocal@openssh.com":
				s.errs <- ch.Reject(ssh.Prohibited, fmt.Sprintf("using %s is prohibited", ch.ChannelType()))
			default:
				s.errs <- ch.Reject(ssh.UnknownChannelType, "unknown channel type")
			}

		case req, ok := <-reqs:
			if !ok {
				reqs = nil
				continue
			}
			s.Debugw("global request", "req", req)
			switch req.Type {
			case "keepalive@openssh.com":
				s.errs <- req.Reply(true, nil)
			case "no-more-sessions@openssh.com":
				s.noMoreSessions = true
			default:
				// "[cancel-]tcpip-forward" falls here
				if req.WantReply {
					s.errs <- req.Reply(false, nil)
				}
			}
		}
	}

	close(s.errs)
}

type User struct {
	Username string
	RemoteHost string
	Port uint16
}

func parseUsername(username string) (*User, error) {
	parts := strings.Split(username, "/")
	if len(parts) > 3 {
		return nil, fmt.Errorf("invalid username provided by client: %s", username)
	}
	result := &User{}
	result.Username = parts[0]

	if len(parts) > 1 {
		result.RemoteHost = parts[1]
	}

	if len(parts) > 2 {
		port, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, errors.Wrap(err, "invalid port value provided")
		}

		result.Port = uint16(port)
	}

	if result.Port == 0 {
		result.Port = DefaultSSHPort
	}

	return result, nil
}

func createCertChecker(conf Config) (*ssh.CertChecker, error) {
	if conf.CAKeys == "" {
		return nil, errors.New("CAKeys parameter not set")
	}

	caKeys, err := readAuthorizedKeys(conf.CAKeys)
	if err != nil {
		return nil, errors.Wrap(err, "cannot read CAKeys")
	}

	return &ssh.CertChecker{
		// TODO: implement source-addr checks
		SupportedCriticalOptions: []string{},
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			_, ok := caKeys[string(auth.Marshal())]
			return ok
		},
		IsRevoked: func(cert *ssh.Certificate) bool {
			// TODO: implement revocation check
			return false
		},
	}, nil
}

func (s *Server) ProcessConnection(nConn net.Conn) (err error) {
	hostKey, err := readHostKey(s.Conf.HostKey)
	if err != nil {
		return errors.Wrap(err, "failed to read host key")
	}

	certChecker, err := createCertChecker(s.Conf)
	if err != nil {
		return errors.Wrap(err, "can't create cert checker")
	}
	s.certChecker = certChecker

	serverConf := &ssh.ServerConfig{
		// OpenSSH-specific extensions compatibility
		ServerVersion:     SSHServerVersion,
		PublicKeyCallback: s.authCallback,
	}
	serverConf.AddHostKey(hostKey)

	conn, chans, globalReqs, err := ssh.NewServerConn(nConn, serverConf)
	if err != nil {
		return errors.Wrap(err, "failed to handshake")
	}
	defer conn.Close()

	s.SugaredLogger = s.SugaredLogger.With(
		"sessionid", conn.SessionID(), // save some space in logs
	)

	user, err := parseUsername(conn.User())
	if err != nil {
		return err
	}
	s.remoteUser, s.remoteHost, s.remotePort = user.Username, user.RemoteHost, user.Port
	s.sessId = conn.SessionID()
	s.sshConn = conn

	s.Infow("authentication succeded", "user", conn.User())

	s.agent = &ClientAgent{
		Mutex:         &sync.Mutex{},
		SugaredLogger: s.SugaredLogger,
		sshConn:       conn,
	}

	s.errs = make(chan error)
	go s.processClient(chans, globalReqs)

	for err := range s.errs {
		if err != nil {
			if _, ok := err.(CriticalError); ok {
				return errors.Wrap(err, "critical error in channel")
			}
			// TODO: write to client?
			s.Warnw("non-critical error in channel", "err", err)
		}
	}
	s.Info("connection closed")
	return nil
}
