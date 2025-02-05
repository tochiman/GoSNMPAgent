/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/comail/colog"
	"github.com/gosnmp/gosnmp"
	"github.com/spf13/cobra"
)

// proxyCmd represents the proxy command
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "SNMP Proxy Mode",
	Long:  "SNMP Proxy Mode",
	Run: func(cmd *cobra.Command, args []string) {
		g := &gosnmp.GoSNMP{
			Target:       ga.Target,
			Port:         ga.TargetPort,
			Community:    ga.community,
			Version:      gosnmp.Version2c,
			Transport:    "quic",
			InsecureMode: true,
			Timeout:      time.Duration(time.Second * 3),
			Retries:      0,
		}

		ga.Snmp = g

		ga.runAgentProxyServer()
	},
}

func init() {
	rootCmd.AddCommand(proxyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// proxyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// proxyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	proxyCmd.Flags().StringVarP(&ga.Target, "target", "t", "127.0.0.1", "ipaddress of SNMPManager ")
	proxyCmd.Flags().Uint16VarP(&ga.TargetPort, "target-port", "P", 1161, "port of SNMPManager ")
	proxyCmd.Flags().StringVarP(&ga.Host, "host", "H", "0.0.0.0", "SNMPAgent is hosting address")
	proxyCmd.Flags().IntVarP(&ga.Port, "port", "p", 1162, "SNMPAgent is hosting port address")
	proxyCmd.Flags().StringVarP(&ga.community, "community", "c", "public", "Specify SNMP Community")
	proxyCmd.Flags().StringVarP(&ga.certPEM, "cert-pem", "C", "localhost/cert.pem", "Specify filepath of certPEM")
	proxyCmd.Flags().StringVarP(&ga.keyPEM, "key-pem", "K", "localhost/key.pem", "Specify filepath of keyPEM")

	// log 出力の設定
	colog.SetDefaultLevel(colog.LDebug)
	colog.SetMinLevel(colog.LTrace)
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lshortfile,
	})
	colog.Register()
}

func (ga *GoSNMPAgent) runAgentProxyServer() {
	var err error
	udpAddress := &net.UDPAddr{
		IP:   net.ParseIP(ga.Host),
		Port: ga.Port,
	}
	ga.conn, err = net.ListenUDP("udp", udpAddress)
	if err != nil {
		log.Fatalln("error:", err)
	}

	// quicAddress := net.JoinHostPort(ga.Target, strconv.Itoa(int(ga.TargetPort)))
	// tlsConf := &tls.Config{
	// 	InsecureSkipVerify: true,
	// 	NextProtos:         []string{"snmp-quic"},
	// }

	// ga.qconn, err = q.DialAddr(context.Background(), quicAddress, tlsConf, nil)
	// if err != nil {
	// 	log.Println("error:", err)
	// }
	// ga.stream, err = ga.qconn.OpenStreamSync(context.Background())
	// if err != nil {
	// 	log.Println("error:", err)
	// }

	log.Println("info: Starting SNMPAgent")

	ga.AddSnmpMib()
	go ga.executeAgentProxy()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	log.Println("info: Shutdown SNMPAgent")
	ga.stopAgentServer()
}

func (ga *GoSNMPAgent) executeAgentProxy() {
	buffer := make([]byte, 4096)
	for {
		n, address, err := ga.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("warning: error reading UDP:", err)
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
		snmpInPkts++
		sP, err := ga.Snmp.SnmpDecodePacket(buffer[:n])

		var oids []string
		for _, vb := range sP.Variables {
			oids = append(oids, vb.Name)
		}

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

		// forward GoSNMPServer
		err = ga.Snmp.Connect()
		if err != nil {
			log.Println("error:", err)
		}
		defer ga.Snmp.QuicTransport.Close()
		switch sP.PDUType {
		case gosnmp.GetRequest:
			res, err := ga.Snmp.Get(oids)
			if err != nil {
				log.Println("warning: SNMP GetRequest Error:", res)
			}
			for i, variable := range res.Variables {
				fmt.Printf("%d: oid: %s ", i, variable.Name)

				// the Value of each variable returned by Get() implements
				// interface{}. You could do a type switch...
				switch variable.Type {
				case gosnmp.OctetString:
					fmt.Printf("string: %s\n", string(variable.Value.([]byte)))
				default:
					// ... or often you're just interested in numeric values.
					// ToBigInt() will return the Value as a BigInt, for plugging
					// into your calculations.
					fmt.Printf("number: %d\n", gosnmp.ToBigInt(variable.Value))
				}
			}
		}

		// return Agent of source
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
