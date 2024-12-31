package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/comail/colog"
	"github.com/spf13/cobra"

	gosnmp "github.com/gosnmp/gosnmp"
	q "github.com/quic-go/quic-go"
)

type GoSNMPAgent struct {
	conn  *net.UDPConn
	qconn q.Connection

	Listener *q.Listener

	Snmp *gosnmp.GoSNMP

	Host string
	Port int

	Target     string
	TargetPort uint16

	quicMode bool
	certPEM  string
	keyPEM   string

	mibList []*mibEnt

	// m *mibdb.MIBDB

	SupportSnmpMIB bool
	snmpCounters   map[string]*uint32
}

type mibEnt struct {
	strOid  string
	oid     []uint16
	objType gosnmp.Asn1BER
	getFunc func(string) interface{}
}

var (
	//.1.3.6.1.2.1.11.1.0
	snmpInPkts uint32
	//.1.3.6.1.2.1.11.2.0
	snmpOutPkts uint32
	//.1.3.6.1.2.1.11.3.0
	snmpInBadVersions uint32
	//.1.3.6.1.2.1.11.4.0
	snmpInBadCommunityNames uint32
	//.1.3.6.1.2.1.11.6.0
	snmpInASNParseErrs uint32
	//.1.3.6.1.2.1.11.15.0
	snmpInGetRequests uint32
	//.1.3.6.1.2.1.11.16.0
	snmpInGetNexts uint32
	//.1.3.6.1.2.1.11.21.0
	snmpOutNoSuchNames uint32
	//.1.3.6.1.2.1.11.28.0
	snmpOutGetResponses uint32
	//.1.3.6.1.2.1.11.29
	snmpOutTraps uint32
)

// このファイルで使う構造体の初期化
var ga = &GoSNMPAgent{}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start-up SNMPAgent",
	Long:  `Start-up SNMPAgent`,
	Run: func(cmd *cobra.Command, args []string) {
		g := &gosnmp.GoSNMP{
			Target:    ga.Target,
			Port:      ga.TargetPort,
			Community: "public",
			Version:   gosnmp.Version2c,
			Timeout:   time.Duration(time.Second * 3),
			Retries:   0,
		}

		ga.Snmp = g

		if ga.quicMode {
			ga.runAgentQUICServer()
		} else if !ga.quicMode {
			ga.runAgentServer()
		}
	},
}

func init() {
	rootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:

	// flagの設定
	runCmd.Flags().BoolVarP(&ga.quicMode, "quic", "q", false, "quic mode")
	runCmd.Flags().StringVarP(&ga.Target, "target", "t", "127.0.0.1", "ipaddress of SNMPManager ")
	runCmd.Flags().Uint16VarP(&ga.TargetPort, "target-port", "p", 1161, "port of SNMPManager ")
	runCmd.Flags().StringVarP(&ga.Host, "host", "H", "0.0.0.0", "SNMPAgent is hosting address")
	runCmd.Flags().IntVarP(&ga.Port, "port", "P", 1161, "SNMPAgent is hosting port address")
	runCmd.Flags().StringVarP(&ga.certPEM, "cert-pem", "c", "localhost/cert.pem", "Specify filepath of certPEM")
	runCmd.Flags().StringVarP(&ga.keyPEM, "key-pem", "k", "localhost/key.pem", "Specify filepath of keyPEM")

	// log 出力の設定
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LTrace)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lshortfile,
	})
	colog.Register()
}

func (ga *GoSNMPAgent) runAgentServer() {
	var err error
	udpAddress := &net.UDPAddr{
		IP:   net.ParseIP(ga.Host),
		Port: ga.Port,
	}

	ga.conn, err = net.ListenUDP("udp", udpAddress)
	if err != nil {
		log.Fatalln("error:", err)
	}
	log.Println("info: Starting GoSNMPAgent")

	// SNMP関連の処理
	ga.AddSnmpMib()
	go ga.executeAgent()
	// err = ga.Snmp.Connect()
	// if err != nil {
	// 	log.Println("error:", err)
	// }

	// 停止できるためにSIGINTを受け取れるようにする
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit // SIGIINTを受け取るまで待機
	log.Println("info: Shutdown SNMP Agent")
	ga.stopAgentServer()

}

func (ga *GoSNMPAgent) runAgentQUICServer() {
	var err error
	address := net.JoinHostPort(ga.Host, strconv.Itoa(ga.Port))
	tlsConfig := generateTLSConfig(ga.certPEM, ga.keyPEM)

	ga.Listener, err = q.ListenAddr(address, tlsConfig, nil)
	if err != nil {
		log.Fatalln("error: ListenAddressError:", err)
	}
	log.Println("info: Starting GoSNMPAgent on QUIC")

	// SNMP関連の処理
	ga.AddSnmpMib()
	go ga.executeAgent()
	// err = ga.Snmp.Connect()
	// if err != nil {
	// 	log.Println("error:", err)
	// }

	// 停止できるためにSIGINTを受け取れるようにする
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit // SIGIINTを受け取るまで待機
	log.Println("info: Shutdown SNMP Agent")
	ga.stopAgentServer()
}

func generateTLSConfig(certFile string, keyFile string) *tls.Config {
	certPEM := fmt.Sprintf("cert/%s", certFile)
	keyPEM := fmt.Sprintf("cert/%s", keyFile)

	tlsCert, err := tls.LoadX509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalln("error: TLSCertError: err")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"snmp-quic"},
	}
}

// Stop snmp agent
func (ga *GoSNMPAgent) stopAgentServer() {
	if ga.quicMode {
		if ga.qconn != nil {
			ga.qconn.CloseWithError(0, "Close Connection of QUIC....")
			ga.qconn = nil
		}
	} else if !ga.quicMode {
		if ga.conn == nil {
			return
		}
		ga.conn.Close()
		// ga.Snmp.Conn.Close()
		ga.conn = nil
	}
}

func toNumOid(s string) []uint16 {
	ret := []uint16{}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			continue
		}
		if n, err := strconv.Atoi(id); err == nil {
			ret = append(ret, uint16(n))
		}
	}
	return ret
}

func cmpOid(oid1, oid2 []uint16) int {
	for i := range oid1 {
		if i >= len(oid2) {
			return 1
		}
		if oid1[i] == oid2[i] {
			continue
		}
		if oid1[i] > oid2[i] {
			return 1
		}
		return -1
	}
	if len(oid1) < len(oid2) {
		return -1
	}
	return 0
}

func (a *GoSNMPAgent) AddMibList(oid string, vbType gosnmp.Asn1BER, get func(string) interface{}) {
	mib := &mibEnt{
		strOid:  oid,
		getFunc: get,
		objType: vbType,
		oid:     toNumOid(oid),
	}
	pos := sort.Search(len(a.mibList), func(i int) bool {
		return cmpOid(mib.oid, a.mibList[i].oid) <= 0
	})
	if pos >= len(a.mibList) {
		a.mibList = append(a.mibList, mib)
		return
	}
	if cmpOid(mib.oid, a.mibList[pos].oid) == 0 {
		log.Printf("AddMibList replace OID=%s", oid)
		a.mibList[pos] = mib
		return
	}
	a.mibList = append(a.mibList[:pos+1], a.mibList[pos:]...)
	a.mibList[pos] = mib
}

func (ga *GoSNMPAgent) findMib(oid string, gNextReq bool) (string, gosnmp.Asn1BER, interface{}, error) {
	noid := toNumOid(oid)

	i := sort.Search(len(ga.mibList), func(i int) bool {
		return cmpOid(noid, ga.mibList[i].oid) <= 0
	})
	if i >= len(ga.mibList) {
		return "", gosnmp.Integer, nil, fmt.Errorf("not found")
	}
	if cmpOid(noid, ga.mibList[i].oid) == 0 {
		if !gNextReq {
			return oid, ga.mibList[i].objType, ga.mibList[i].getFunc(oid), nil
		}
		i++
		if i >= len(ga.mibList) {
			return "", gosnmp.Integer, nil, fmt.Errorf("not found")
		}
	}
	oid = ga.mibList[i].strOid
	return oid, ga.mibList[i].objType, ga.mibList[i].getFunc(oid), nil
}

func (ga *GoSNMPAgent) executeAgent() {
	buffer := make([]byte, 4096)
	if ga.quicMode {
		for {
			conn, err := ga.Listener.Accept(context.Background())
			if err != nil {
				log.Println("error: AcceptingConnectionError:", err)
				break
			}
			ga.qconn = conn
			remoteAddr := conn.RemoteAddr()
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				if err == context.DeadlineExceeded {
					// タイムアウトが発生した場合の処理
					log.Println("error: DeadlineExceeded", err)
					continue
				} else {
					log.Println("warning: AcceptStreamWarninng:", err)
				}
			}
			counts, err := stream.Read(buffer)
			if err != nil {
				log.Println("warning: Can't Read Stream:", err)
			}
			log.Println("info: quic request from", remoteAddr, ".", "size=", counts)
			// パケットを解析
			snmpInPkts++
			sP, err := ga.Snmp.SnmpDecodePacket(buffer[:counts])
			if err != nil {
				snmpInASNParseErrs++
				log.Println("error:", err)
			}
			if sP.Version == gosnmp.Version3 {
				snmpInBadVersions++
				log.Println("error: Drop SNMP v3 request")
				continue
			}
			if sP.Community != ga.Snmp.Community {
				snmpInBadCommunityNames++
				log.Println("Drop Invalid Community request")
				continue
			}
			if sP.PDUType != gosnmp.GetRequest && sP.PDUType != gosnmp.GetNextRequest {
				snmpInBadCommunityNames++
				log.Printf("error: Drop Bad PDU Type=%v", sP.PDUType)
				continue
			}
			bNext := sP.PDUType == gosnmp.GetNextRequest
			if !bNext {
				snmpInGetRequests++
			} else {
				snmpInGetNexts++
			}

			pdus := []gosnmp.SnmpPDU{}
			errIndex := -1
			for i, vb := range sP.Variables {
				o, t, m, err := ga.findMib(vb.Name, bNext)
				if err == nil {
					vb.Name = o
					vb.Type = t
					vb.Value = m
				} else if errIndex == -1 {
					errIndex = i
				}
				pdus = append(pdus, vb)
			}
			out, err := ga.Snmp.SnmpEncodeGetResponsePacket(sP.RequestID, int32(errIndex), pdus)
			if err != nil {
				continue
			}
			if errIndex != -1 {
				snmpOutNoSuchNames++
			}
			if conn == nil {
				return
			}
			snmpOutGetResponses++
			snmpOutPkts++
			stream.Write(out)
		}
	} else if !ga.quicMode {
		for {
			// UDPデータを受信
			n, address, err := ga.conn.ReadFromUDP(buffer)
			log.Println(n)
			if err != nil {
				log.Println("error reading UDP:", err)
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					continue
				}
				break
			}
			if address == nil {
				log.Println("warning: received packet with nil address")
				continue
			}
			log.Printf("info: Received packet from %v", address)
			// パケットを解析
			snmpInPkts++
			sP, err := ga.Snmp.SnmpDecodePacket(buffer[:n])
			if err != nil {
				snmpInASNParseErrs++
				log.Println("error:", err)
			}
			if sP.Version == gosnmp.Version3 {
				snmpInBadVersions++
				log.Println("error: Drop SNMP v3 request")
				continue
			}
			if sP.Community != ga.Snmp.Community {
				snmpInBadCommunityNames++
				log.Println("Drop Invalid Community request")
				continue
			}
			if sP.PDUType != gosnmp.GetRequest && sP.PDUType != gosnmp.GetNextRequest {
				snmpInBadCommunityNames++
				log.Printf("error: Drop Bad PDU Type=%v", sP.PDUType)
				continue
			}
			bNext := sP.PDUType == gosnmp.GetNextRequest
			if !bNext {
				snmpInGetRequests++
			} else {
				snmpInGetNexts++
			}

			pdus := []gosnmp.SnmpPDU{}
			errIndex := -1
			for i, vb := range sP.Variables {
				o, t, m, err := ga.findMib(vb.Name, bNext)
				if err == nil {
					vb.Name = o
					vb.Type = t
					vb.Value = m
				} else if errIndex == -1 {
					errIndex = i
				}
				pdus = append(pdus, vb)
			}
			out, err := ga.Snmp.SnmpEncodeGetResponsePacket(sP.RequestID, int32(errIndex), pdus)
			if err != nil {
				continue
			}
			if errIndex != -1 {
				snmpOutNoSuchNames++
			}
			if ga.conn == nil {
				return
			}
			snmpOutGetResponses++
			snmpOutPkts++
			ga.conn.WriteTo(out, address)
		}
	}
}

func (a *GoSNMPAgent) getCounter32(oid string) interface{} {
	if p, ok := a.snmpCounters[oid]; ok {
		return *p
	}
	return uint32(0)
}

func (ga *GoSNMPAgent) getSnmpEnableAuthenTraps(oid string) interface{} {
	return 2
}

func (ga *GoSNMPAgent) AddSnmpMib() {
	if !ga.SupportSnmpMIB {
		return
	}
	ga.snmpCounters = make(map[string]*uint32)
	snmpInPkts = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.1.0"] = &snmpInPkts
	snmpOutPkts = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.2.0"] = &snmpOutPkts
	snmpInBadVersions = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.3.0"] = &snmpInBadVersions
	snmpInBadCommunityNames = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.4.0"] = &snmpInBadCommunityNames
	snmpInASNParseErrs = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.6.0"] = &snmpInASNParseErrs
	snmpInGetRequests = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.15.0"] = &snmpInGetRequests
	snmpInGetNexts = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.16.0"] = &snmpInGetNexts
	snmpOutNoSuchNames = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.21.0"] = &snmpOutNoSuchNames
	snmpOutGetResponses = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.28.0"] = &snmpOutGetResponses
	snmpOutTraps = 0
	ga.snmpCounters[".1.3.6.1.2.1.11.29.0"] = &snmpOutTraps
	for i := 1; i < 30; i++ {
		if i == 7 || i == 23 {
			continue
		}
		ga.AddMibList(fmt.Sprintf(".1.3.6.1.2.1.11.%d.0", i), gosnmp.Counter32, ga.getCounter32)
	}
	ga.AddMibList(".1.3.6.1.2.1.11.30.0", gosnmp.Integer, ga.getSnmpEnableAuthenTraps)
}
