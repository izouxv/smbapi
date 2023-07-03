package smb

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/izouxv/logx"
	"golang.org/x/net/webdav"
)

var treeIdX = uint32(0)

func NewAnchor(name, rootpath string) *Anchor {
	return &Anchor{Name: name, RootPath: rootpath, tid: atomic.AddUint32(&treeId, 1)}
}

type Handler struct {
	*webdav.Handler
	// symlink WIP
}

type Anchor struct {
	Name     string
	RootPath string
	tid      uint32
	Handle   *Handler
}
type GetPwdFunc func(name string) (password string, err error)
type GetAnchorFun func(userName string) (anchors []*Anchor, err error)

type Config struct {
	// Port int
	Pwd    GetPwdFunc
	Tree   GetAnchorFun
	Handle func(string) *Handler
}
type ServerI interface {
	Start(PORT int)
}

func NewServer(config *Config) ServerI {
	return &server{config: config, sessions: make(map[uint64]SessionS)}
}

type server struct {
	config   *Config
	sessions map[uint64]SessionS
}

func (s *server) Start(PORT int) {
	// PORT := s.config.Port
	getPwd := s.config.Pwd
	getTree := s.config.Tree
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", PORT))
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Printf("Listening on %v port\n", PORT)
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}

		logx.Printf("IP: %v", conn.RemoteAddr().String())

		// Handle connections in a new goroutine.
		go s.HandleConnection(conn, getPwd, getTree)

	}
}

func (s *server) HandleConnection(conn net.Conn, getPwd GetPwdFunc, getTree GetAnchorFun) {
	remoteAddr := conn.RemoteAddr()
	defer func() {
		if err := recover(); err != nil {
			b := make([]byte, 4000, 4000)
			n := runtime.Stack(b, false)
			fmt.Printf("%s\n", b[:n])
			fmt.Printf("Error(%v): %s\n\n", remoteAddr, err)
		}
	}()
	defer conn.Close()

	session := NewSessionServer(true, conn, getPwd, getTree)

	if err := session.NegotiateProtocolServer(); err != nil {
		logx.Infof("login failed, %v, err: %v", session.IsAuthenticated, err)
		// time.Sleep(time.Second)
		// conn.Close()
		return
	}

	if !session.IsAuthenticated {
		logx.Infof("login failed, %v", session.IsAuthenticated)
		time.Sleep(time.Second)
		conn.Close()
		return
	}

	logx.Infof("login suc, %v", session.IsAuthenticated)

	rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	for {
		reqMsg, _, err := session.Recv(rw)
		if err != nil {
			return
		}
		respBuf, cmd, stat := ActionFunc(NewDataCtx(session, conn, s.config.Handle), reqMsg)
		if stat != StatusOk {
			return
		}

		if false {
			logx.Printf("\n\n\ncmd: %v req:\n%vresp:\n%v", cmd.String(), hex.Dump(reqMsg), hex.Dump(respBuf))
		}

		session.Send(respBuf, rw)
	}
}
