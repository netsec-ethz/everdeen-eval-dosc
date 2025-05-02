package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"image/color"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/scionproto/scion/scion-pki/testcrypto"

	"gonum.org/v1/plot"
	"gonum.org/v1/plot/plotter"
	"gonum.org/v1/plot/vg"
	"gonum.org/v1/plot/vg/draw"
	"gonum.org/v1/plot/vg/vgpdf"
)

const (
	envAWS_SECURITY_GROUP_ID = "AWS_SECURITY_GROUP_ID"
	envAWS_SUBNET_ID         = "AWS_SUBNET_ID"

	envSSH_ID             = "SSH_ID"
	envSSH_SECRET_ID_FILE = "SSH_SECRET_ID_FILE"

	ec2ImageId                       = "ami-0162a5964814a3efa"
	ec2InstanceCount                 = 6
	ec2InstanceNamePrefix            = "ec2-test-"
	ec2InstancePrivateIpAddressCount = 3
	ec2InstanceStateRunning          = 16
	ec2InstanceStateTerminated       = 48
	ec2InstanceType                  = types.InstanceTypeT4gXlarge
	ec2InstanceUser                  = "ec2-user"
	ec2ReferenceClockAddr            = "169.254.169.123"
	ec2Region                        = "eu-central-2"

	modeIP    = "ip"
	modeSCION = "scion"

	svcAS_A_INFRA = "AS_A_INFRA"
	svcAS_B_INFRA = "AS_B_INFRA"
	svcAS_C_INFRA = "AS_C_INFRA"
	svcAS_A_TS    = "AS_A_TS"
	svcAS_B_TS    = "AS_B_TS"
	svcLGS        = "LGS"
	svcLGC        = "LGC"
	svcREFC       = "REFC"

	attackTargetSCION = "192.0.2.1"
)

var (
	attackCount = map[string]int{
		modeIP:    1,
		modeSCION: 4,
	}
	attackPreparation = map[string]time.Duration{
		modeIP:    30 * time.Second,
		modeSCION: 60 * time.Second,
	}
	attackDuration = map[string]time.Duration{
		modeIP:    150 * time.Second,
		modeSCION: 300 * time.Second,
	}
	installChronyCommands = []string{
		"sudo yum update",
		"sudo yum install -y git gcc make",
		"curl -LO https://chrony-project.org/releases/chrony-4.6.1.tar.gz",
		"tar -xzvf chrony-4.6.1.tar.gz ",
		"rm chrony-4.6.1.tar.gz",
		"mv chrony-4.6.1 chrony-4.6.1-src",
		"mkdir chrony-4.6.1",
		"cd /home/ec2-user/chrony-4.6.1-src && ./configure --prefix=/home/ec2-user/chrony-4.6.1",
		"cd /home/ec2-user/chrony-4.6.1-src && make install",
	}
	installIPerf3Commands = []string{
		"sudo yum update",
		"sudo yum install -y iperf3",
	}
	installIProuteCommands = []string{
		"sudo yum update",
		"sudo yum install -y iproute-tc",
	}
	installNtimedToolCommands = []string{
		"sudo yum update",
		"sudo yum install -y gcc",
		"cd /home/ec2-user && gcc -Wall dist/src/ntimed-tool.c -o dist/bin/arm64/ntimed-tool -lm",
	}
	installSCIONCommands = []string{
		"cd /home/ec2-user/dist/bin/arm64 && chmod a+x *",
	}
	startServicesCommands = map[string]map[string][]string{
		modeIP: {
			svcAS_A_INFRA: {
				"sudo sysctl -w net.ipv4.ip_forward=1",
				"sudo sysctl -w net.ipv6.conf.all.forwarding=1",
				"sudo ip route add $AS_B_TS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
				"sudo ip route add $AS_A_TS_IP_0/32 via $AS_A_TS_IP_0 dev ens5",
			},
			svcAS_B_INFRA: {
				"sudo sysctl -w net.ipv4.ip_forward=1",
				"sudo sysctl -w net.ipv6.conf.all.forwarding=1",
				"sudo ip route add $AS_A_TS_IP_0/32 via $AS_A_INFRA_IP_0 dev ens5",
				"sudo ip route add $AS_B_TS_IP_0/32 via $AS_B_TS_IP_0 dev ens5",
				"sudo ip route add $LGS_IP_0/32 via $LGS_IP_0 dev ens5",
				"sudo ip route add $LGC_IP_0/32 via $LGC_IP_0 dev ens5",
				"sudo tc qdisc add dev ens5 root handle 1: htb default 7",
				"sudo tc class add dev ens5 parent 1:0 classid 1:1 htb rate 5000mbit",
				"sudo tc class add dev ens5 parent 1:1 classid 1:2 htb rate 100kbit prio 1",
				"sudo tc class add dev ens5 parent 1:1 classid 1:3 htb rate 100kbit prio 1",
				"sudo tc class add dev ens5 parent 1:1 classid 1:4 htb rate 1500mbit prio 2",
				"sudo tc class add dev ens5 parent 1:1 classid 1:5 htb rate 1500mbit prio 2",
				"sudo tc class add dev ens5 parent 1:1 classid 1:6 htb rate 1500mbit prio 2",
				"sudo tc class add dev ens5 parent 1:1 classid 1:7 htb rate 450mbit prio 3",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 1 u32 match ip tos 0xb8 0xff match ip dst $AS_A_TS_IP_0/32 flowid 1:2",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 1 u32 match ip tos 0xb8 0xff match ip dst $AS_B_TS_IP_0/32 flowid 1:3",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $AS_A_TS_IP_0/32 flowid 1:4",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $AS_B_TS_IP_0/32 flowid 1:5",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $LGS_IP_0/32 flowid 1:5",
				"sudo tc filter add dev ens5 parent 1:0 protocol ip prio 2 u32 match ip dst $LGC_IP_0/32 flowid 1:6",
			},
			svcAS_A_TS: {
				"sudo ip route add $AS_B_TS_IP_0/32 via $AS_A_INFRA_IP_0 dev ens5",
				"ln -sf /home/ec2-user/testnet/ip/chrony_0_0.conf /home/ec2-user/testnet/ip/chrony_0.conf",
				"sudo cp /home/ec2-user/testnet/ip/chrony@.service /lib/systemd/system/chrony@0.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable chrony@0.service",
				"sudo systemctl start chrony@0.service",
			},
			svcAS_B_TS: {
				"sudo ip route add $AS_A_TS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
				"ln -sf /home/ec2-user/testnet/ip/chrony_1_0.conf /home/ec2-user/testnet/ip/chrony_1.conf",
				"sudo cp /home/ec2-user/testnet/ip/chrony@.service /lib/systemd/system/chrony@1.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable chrony@1.service",
				"sudo systemctl start chrony@1.service",
			},
			svcLGS: {
				"sudo ip route add $LGC_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
				"sudo cp /home/ec2-user/testnet/ip/iperf3.service /lib/systemd/system/iperf3.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable iperf3.service",
				"sudo systemctl start iperf3.service",
			},
			svcLGC: {
				"sudo ip route add $LGS_IP_0/32 via $AS_B_INFRA_IP_0 dev ens5",
			},
		},
		modeSCION: {
			svcAS_A_INFRA: {
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_110.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_110.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_110.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_110.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable scion-border-router@ASff00_0_110.service",
				"sudo systemctl enable scion-control-service@ASff00_0_110.service",
				"sudo systemctl enable scion-daemon@ASff00_0_110.service",
				"sudo systemctl enable scion-dispatcher@ASff00_0_110.service",
				"sudo systemctl start scion-border-router@ASff00_0_110.service",
				"sudo systemctl start scion-control-service@ASff00_0_110.service",
				"sudo systemctl start scion-daemon@ASff00_0_110.service",
				"sudo systemctl start scion-dispatcher@ASff00_0_110.service",
			},
			svcAS_B_INFRA: {
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_120.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_120.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_120.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_120.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable scion-border-router@ASff00_0_120.service",
				"sudo systemctl enable scion-control-service@ASff00_0_120.service",
				"sudo systemctl enable scion-daemon@ASff00_0_120.service",
				"sudo systemctl enable scion-dispatcher@ASff00_0_120.service",
				"sudo systemctl start scion-border-router@ASff00_0_120.service",
				"sudo systemctl start scion-control-service@ASff00_0_120.service",
				"sudo systemctl start scion-daemon@ASff00_0_120.service",
				"sudo systemctl start scion-dispatcher@ASff00_0_120.service",
			},
			svcAS_C_INFRA: {
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-border-router@.service /lib/systemd/system/scion-border-router@ASff00_0_130.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-control-service@.service /lib/systemd/system/scion-control-service@ASff00_0_130.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_130.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-dispatcher@.service /lib/systemd/system/scion-dispatcher@ASff00_0_130.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable scion-border-router@ASff00_0_130.service",
				"sudo systemctl enable scion-control-service@ASff00_0_130.service",
				"sudo systemctl enable scion-daemon@ASff00_0_130.service",
				"sudo systemctl enable scion-dispatcher@ASff00_0_130.service",
				"sudo systemctl start scion-border-router@ASff00_0_130.service",
				"sudo systemctl start scion-control-service@ASff00_0_130.service",
				"sudo systemctl start scion-daemon@ASff00_0_130.service",
				"sudo systemctl start scion-dispatcher@ASff00_0_130.service",
			},
			svcAS_A_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_110_TS_DSCP_0.toml /home/ec2-user/testnet/scion/ASff00_0_110_TS.toml",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_110.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-timeservice-server.service /lib/systemd/system/scion-timeservice-server@ASff00_0_110.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable scion-daemon@ASff00_0_110.service",
				"sudo systemctl enable scion-timeservice-server@ASff00_0_110.service",
				"sudo systemctl start scion-daemon@ASff00_0_110.service",
				"sudo systemctl start scion-timeservice-server@ASff00_0_110.service",
			},
			svcAS_B_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_120_TS_DSCP_0.toml /home/ec2-user/testnet/scion/ASff00_0_120_TS.toml",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-daemon@.service /lib/systemd/system/scion-daemon@ASff00_0_120.service",
				"sudo cp /home/ec2-user/testnet/scion/systemd/scion-timeservice-client.service /lib/systemd/system/scion-timeservice-client@ASff00_0_120.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable scion-daemon@ASff00_0_120.service",
				"sudo systemctl enable scion-timeservice-client@ASff00_0_120.service",
				"sudo systemctl start scion-daemon@ASff00_0_120.service",
				"sudo systemctl start scion-timeservice-client@ASff00_0_120.service",
			},
			svcREFC: {
				"sudo cp /home/ec2-user/testnet/scion/systemd/chrony.service /lib/systemd/system/chrony.service",
				"sudo systemctl daemon-reload",
				"sudo systemctl enable chrony.service",
				"sudo systemctl start chrony.service",
			},
		},
	}
	setDSCPValue0Commands = map[string]map[string][]string{
		modeIP: {
			svcAS_A_TS: {
				"sudo systemctl stop chrony@0.service",
				"ln -sf /home/ec2-user/testnet/ip/chrony_0_0.conf /home/ec2-user/testnet/ip/chrony_0.conf",
				"sudo systemctl start chrony@0.service",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
			},
			svcAS_B_TS: {
				"sudo systemctl stop chrony@1.service",
				"ln -sf /home/ec2-user/testnet/ip/chrony_1_0.conf /home/ec2-user/testnet/ip/chrony_1.conf",
				"sudo systemctl start chrony@1.service",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
			},
		},
		modeSCION: {
			svcAS_A_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_110_TS_DSCP_0.toml /home/ec2-user/testnet/scion/ASff00_0_110_TS.toml",
				"sudo systemctl restart scion-timeservice-server@ASff00_0_110.service",
			},
			svcAS_B_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_120_TS_DSCP_0.toml /home/ec2-user/testnet/scion/ASff00_0_120_TS.toml",
				"sudo systemctl restart scion-timeservice-client@ASff00_0_120.service",
			},
		},
	}
	setDSCPValue46Commands = map[string]map[string][]string{
		modeIP: {
			svcAS_A_TS: {
				"sudo systemctl stop chrony@0.service",
				"ln -sf /home/ec2-user/testnet/ip/chrony_0_46.conf /home/ec2-user/testnet/ip/chrony_0.conf",
				"sudo systemctl start chrony@0.service",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
			},
			svcAS_B_TS: {
				"sudo systemctl stop chrony@1.service",
				"ln -sf /home/ec2-user/testnet/ip/chrony_1_46.conf /home/ec2-user/testnet/ip/chrony_1.conf",
				"sudo systemctl start chrony@1.service",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
				"sudo chronyc makestep",
			},
		},
		modeSCION: {
			svcAS_A_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_110_TS_DSCP_46.toml /home/ec2-user/testnet/scion/ASff00_0_110_TS.toml",
				"sudo systemctl restart scion-timeservice-server@ASff00_0_110.service",
			},
			svcAS_B_TS: {
				"ln -sf /home/ec2-user/testnet/scion/ASff00_0_120_TS_DSCP_46.toml /home/ec2-user/testnet/scion/ASff00_0_120_TS.toml",
				"sudo systemctl restart scion-timeservice-client@ASff00_0_120.service",
			},
		},
	}
	runAttackCommand = map[string]string{
		modeIP:    "iperf3 -c $TARGET_IP -u -b 5000M -t 120",
		modeSCION: "(echo \"0\" | /home/ec2-user/dist/bin/arm64/scion ping -i 1-ff00:0:120,$TARGET_IP --interval 1ms) || true",
	}
	measureOffsetsCommand = map[string]string{
		modeIP:    "while true; do /home/ec2-user/dist/bin/arm64/ntimed-tool $REFC_IP; sleep 1; done\n",
		modeSCION: "/home/ec2-user/dist/bin/arm64/timeservice tool -local 0-0,0.0.0.0 -remote 0-0,$REFC_IP:123 -periodic\n",
	}
	testnetDir = map[string]string{
		modeIP:    "testnet/ip",
		modeSCION: "testnet/scion",
	}
	testnetServices = map[string][]string{
		modeIP: {
			svcAS_A_INFRA,
			svcAS_B_INFRA,
			svcAS_A_TS,
			svcAS_B_TS,
			svcLGS,
			svcLGC,
		},
		modeSCION: {
			svcAS_A_INFRA,
			svcAS_B_INFRA,
			svcAS_C_INFRA,
			svcAS_A_TS,
			svcAS_B_TS,
			svcREFC,
		},
	}
	testnetTemplates = map[string]map[string]bool{
		modeIP: {
			"testnet/ip/chrony_1_0.conf":  true,
			"testnet/ip/chrony_1_46.conf": true,
		},
		modeSCION: {
			"testnet/scion/gen/ASff00_0_110/topology.json": true,
			"testnet/scion/gen/ASff00_0_120/topology.json": true,
			"testnet/scion/gen/ASff00_0_130/topology.json": true,
			"testnet/scion/ASff00_0_110_TS_DSCP_0.toml":    true,
			"testnet/scion/ASff00_0_110_TS_DSCP_46.toml":   true,
			"testnet/scion/ASff00_0_120_TS_DSCP_0.toml":    true,
			"testnet/scion/ASff00_0_120_TS_DSCP_46.toml":   true,
		},
	}
	testnetCryptoPaths = []string{
		"testnet/scion/gen/certs",
		"testnet/scion/gen/ISD1",
		"testnet/scion/gen/trcs",
		"testnet/scion/gen/ASff00_0_110/certs",
		"testnet/scion/gen/ASff00_0_110/crypto",
		"testnet/scion/gen/ASff00_0_110/keys",
		"testnet/scion/gen/ASff00_0_120/certs",
		"testnet/scion/gen/ASff00_0_120/crypto",
		"testnet/scion/gen/ASff00_0_120/keys",
		"testnet/scion/gen/ASff00_0_130/certs",
		"testnet/scion/gen/ASff00_0_130/crypto",
		"testnet/scion/gen/ASff00_0_130/keys",
	}
	testnetCryptoMasterKeys = []string{
		"testnet/scion/gen/ASff00_0_110/keys/master0.key",
		"testnet/scion/gen/ASff00_0_110/keys/master1.key",
		"testnet/scion/gen/ASff00_0_120/keys/master0.key",
		"testnet/scion/gen/ASff00_0_120/keys/master1.key",
		"testnet/scion/gen/ASff00_0_130/keys/master0.key",
		"testnet/scion/gen/ASff00_0_130/keys/master1.key",
	}
	testnetCertDirs = []string{
		"testnet/scion/gen/ASff00_0_110/certs",
		"testnet/scion/gen/ASff00_0_120/certs",
		"testnet/scion/gen/ASff00_0_130/certs",
	}
	testnetGenDir      = "testnet/scion/gen"
	testnetTRCDir      = "testnet/scion/gen/trcs"
	testnetTLSCertFile = "testnet/scion/gen/tls.crt"
	testnetTLSKeyFile  = "testnet/scion/gen/tls.key"
	testnetTopology    = "testnet/scion/topology.topo"
)

func newEC2Client() *ec2.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(ec2Region))
	if err != nil {
		log.Fatalf("LoadDefaultConfig failed: %v", err)
	}
	return ec2.NewFromConfig(cfg)
}

func listInstances(mode string) {
	client := newEC2Client()
	res, err := client.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{},
	)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range res.Reservations {
		for _, i := range r.Instances {
			sort.Slice(i.Tags, func(x, y int) bool {
				return *i.Tags[x].Key < *i.Tags[y].Key
			})
			for _, t := range i.Tags {
				if *t.Key == "Name" && (*t.Value == ec2InstanceNamePrefix+mode ||
					mode == "" && strings.HasPrefix(*t.Value, ec2InstanceNamePrefix)) {
					fmt.Print(*i.InstanceId)
					fmt.Print(", ", i.State.Name)
					if i.PublicIpAddress != nil {
						fmt.Printf(", %15s", *i.PublicIpAddress)
					}
					for _, tt := range i.Tags {
						if *tt.Key == "Name" {
							fmt.Print(", ", *tt.Key, "=", *tt.Value)
						}
					}
					for _, tt := range i.Tags {
						if *tt.Key != "Name" {
							fmt.Print(", ", *tt.Key, "=", *tt.Value)
						}
					}
					fmt.Println()
				}
			}
		}
	}
}

func sshIdentity(path string) ssh.AuthMethod {
	key, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("ReadFile (%s) failed: %v", path, err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("ParsePrivateKey (%s) failed: %v", path, err)
	}
	return ssh.PublicKeys(signer)
}

func dialSSH(instanceAddr string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: ec2InstanceUser,
		Auth: []ssh.AuthMethod{
			sshIdentity(os.Getenv(envSSH_SECRET_ID_FILE)),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	hostAddr := fmt.Sprintf("%s:22", instanceAddr)
	var sshClient *ssh.Client
	var err error
	for i := 0; i < 60; i++ {
		sshClient, err = ssh.Dial("tcp", hostAddr, sshConfig)
		if err == nil {
			return sshClient, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func createLogFile(name string) (*os.File, error) {
	err := os.MkdirAll("logs", 0755)
	if err != nil {
		return nil, err
	}
	fn := fmt.Sprintf("./logs/%s", name)
	return os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
}

func openLogFile(name string) (*os.File, error) {
	err := os.MkdirAll("logs", 0755)
	if err != nil {
		return nil, err
	}
	fn := fmt.Sprintf("./logs/%s", name)
	return os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func runCommand(sshClient *ssh.Client, id, command string) {
	f, err := openLogFile(id)
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	defer f.Close()
	sess, err := sshClient.NewSession()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	defer sess.Close()
	f.WriteString(fmt.Sprintf("$ %s\n", command))
	var wg sync.WaitGroup
	sessStdout, err := sess.StdoutPipe()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(f, sessStdout)
	}()
	sessStderr, err := sess.StderrPipe()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(f, sessStderr)
	}()
	err = sess.Run(command)
	wg.Wait()
	if err != nil {
		log.Printf("Failed to run command %s (%s): %v", id, command, err)
	}
}

func runCommands(sshClient *ssh.Client, instanceId, instanceAddr string, commands []string) {
	id := fmt.Sprintf("%s-%s", instanceId, instanceAddr)
	for _, command := range commands {
		runCommand(sshClient, id, command)
	}
}

func uploadFile(client *sftp.Client, dst, src string, mode string, data map[string]string) {
	d, err := client.Create(dst)
	if err != nil {
		log.Fatal(err)
	}
	defer d.Close()
	if testnetTemplates[mode][src] {
		s, err := template.ParseFiles(src)
		if err != nil {
			log.Fatal(err)
		}
		err = s.Execute(d, data)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		s, err := os.Open(src)
		if err != nil {
			log.Fatal(err)
		}
		defer s.Close()
		_, err = d.ReadFrom(s)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func uploadDir(client *sftp.Client, dst, src string, mode string, data map[string]string) {
	es, err := os.ReadDir(src)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range es {
		n := e.Name()
		if n[0] != '.' {
			s := filepath.Join(src, n)
			d := filepath.Join(dst, n)
			if e.IsDir() {
				err = client.Mkdir(d)
				if err != nil {
					log.Fatalf("Mkdir failed: %v", err)
				}
				uploadDir(client, d, s, mode, data)
			} else if e.Type().IsRegular() {
				uploadFile(client, d, s, mode, data)
			}
		}
	}
}

func uploadTestnet(sshc *ssh.Client, mode string, data map[string]string) {
	sftpc, err := sftp.NewClient(sshc)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer sftpc.Close()
	d := strings.Split(testnetDir[mode], string(os.PathSeparator))
	p := ""
	for i := 0; i != len(d); i++ {
		if i != 0 {
			p += string(os.PathSeparator)
		}
		p += d[i]
		err = sftpc.Mkdir(p)
		if err != nil {
			log.Fatalf("Mkdir failed: %v", err)
		}
	}
	uploadDir(sftpc, testnetDir[mode], testnetDir[mode], mode, data)
}

func uploadDist(sshc *ssh.Client) {
	sftpc, err := sftp.NewClient(sshc)
	if err != nil {
		log.Fatal(err)
		return
	}
	err = sftpc.Mkdir("dist")
	if err != nil {
		log.Fatalf("Mkdir failed: %v", err)
	}
	uploadDir(sftpc, "dist", "dist", "", nil)
}

func fixupServiceAddrs(commands, services []string, data map[string]string) {
	for i := range commands {
		for _, s := range services {
			commands[i] = strings.ReplaceAll(commands[i], "$"+s+"_IP_0", data[s+"_IP_0"])
		}
	}
}

func startServices(sshClient *ssh.Client, instanceId, instanceAddr, mode string, data map[string]string) {
	role := data[instanceId]
	commands := startServicesCommands[mode][role]
	fixupServiceAddrs(commands, testnetServices[mode], data)
	runCommands(sshClient, instanceId, instanceAddr, commands)
}

func installChrony(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installChronyCommands)
}

func installIPerf3(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installIPerf3Commands)
}

func installIProute(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installIProuteCommands)
}

func installNtimedTool(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installNtimedToolCommands)
}

func installSCION(sshClient *ssh.Client, instanceId, instanceAddr string) {
	runCommands(sshClient, instanceId, instanceAddr, installSCIONCommands)
}

func addSecondaryAddrs(sshClient *ssh.Client, instanceId, instanceAddr string, data map[string]string) {
	role := data[instanceId]
	if role != "" {
		for k := 1; k < ec2InstancePrivateIpAddressCount; k++ {
			addr := data[role+"_IP_"+strconv.Itoa(k)]
			if addr != "" {
				id := fmt.Sprintf("%s-%s", instanceId, instanceAddr)
				cmd := fmt.Sprintf("sudo ip address add %s/32 dev ens5 noprefixroute || true", addr)
				runCommand(sshClient, id, cmd)
			}
		}
	}
}

func setupInstance(wg *sync.WaitGroup, instanceId, instanceAddr string, mode string, data map[string]string) {
	defer wg.Done()
	log.Printf("Connecting to instance %s...\n", instanceId)
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceId, err)
		return
	}
	defer sshClient.Close()
	if mode == modeSCION {
		addSecondaryAddrs(sshClient, instanceId, instanceAddr, data)
	}
	log.Printf("Installing software on instance %s...\n", instanceId)
	uploadDist(sshClient)
	switch mode {
	case modeIP:
		installIProute(sshClient, instanceId, instanceAddr)
		installIPerf3(sshClient, instanceId, instanceAddr)
		installNtimedTool(sshClient, instanceId, instanceAddr)
		installChrony(sshClient, instanceId, instanceAddr)
	case modeSCION:
		installSCION(sshClient, instanceId, instanceAddr)
		installChrony(sshClient, instanceId, instanceAddr)
	}
	log.Printf("Installing configuration files on instance %s...\n", instanceId)
	uploadTestnet(sshClient, mode, data)
	log.Printf("Starting %s services on instance %s...\n", data[instanceId], instanceId)
	startServices(sshClient, instanceId, instanceAddr, mode, data)
}

func genTLSCertificate() {
	// Based on go/src/crypto/tls/generate_cert.go
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(28 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	certFile, err := os.Create(testnetTLSCertFile)
	if err != nil {
		log.Fatalf("Failed to create tls.crt for writing: %v", err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		log.Fatalf("Failed to write data to tls.crt: %v", err)
	}
	keyFile, err := os.OpenFile(testnetTLSKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create tls.key for writing: %v", err)
	}
	defer keyFile.Close()
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	err = pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		log.Fatalf("Failed to write data to tls.key: %v", err)
	}
}

type commandPather string

func (s commandPather) CommandPath() string {
	return string(s)
}

func delCryptoMaterial() {
	for _, p := range testnetCryptoPaths {
		_ = os.RemoveAll(p)
	}
	_ = os.Remove(testnetTLSCertFile)
	_ = os.Remove(testnetTLSKeyFile)
}

func genCryptoMaterial() {
	delCryptoMaterial()
	cmd := testcrypto.Cmd(commandPather(""))
	cmd.SetArgs([]string{"-t", testnetTopology, "-o", testnetGenDir, "--as-validity", "28d"})
	stdout, stderr := os.Stdout, os.Stderr
	null, err := os.Open(os.DevNull)
	if err != nil {
		panic(err)
	}
	func() {
		os.Stdout, os.Stderr = null, null
		defer func() {
			os.Stdout, os.Stderr = stdout, stderr
		}()
		err = cmd.Execute()
	}()
	if err != nil {
		log.Fatalf("testcrypto failed: %v", err)
	}
	genMasterKeyFile := func(name string) {
		x := make([]byte, 16)
		n, err := rand.Read(x)
		if err != nil {
			panic(err)
		}
		if n != len(x) {
			panic("rand.Read failed")
		}
		f, err := os.Create(name)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		b := make([]byte, base64.StdEncoding.EncodedLen(len(x)))
		base64.StdEncoding.Encode(b, x)
		n, err = f.Write(b)
		if err != nil {
			panic(err)
		}
		if n != len(b) {
			panic("Write failed")
		}
	}
	for _, k := range testnetCryptoMasterKeys {
		genMasterKeyFile(k)
	}
	copyDir := func(src, dst string) {
		es, err := os.ReadDir(src)
		if err != nil {
			log.Fatal(err)
		}
		for _, e := range es {
			n := e.Name()
			if n[0] != '.' {
				if e.IsDir() {
					panic("not yet implemented")
				} else if e.Type().IsRegular() {
					copyFile := func(src, dst string) {
						s, err := os.Open(src)
						if err != nil {
							log.Fatal(err)
						}
						defer s.Close()
						d, err := os.Create(dst)
						if err != nil {
							panic(err)
						}
						defer d.Close()
						_, err = d.ReadFrom(s)
						if err != nil {
							log.Fatal(err)
						}
					}
					copyFile(filepath.Join(src, n), filepath.Join(dst, n))
				}
			}
		}
	}
	for _, dst := range testnetCertDirs {
		copyDir(testnetTRCDir, dst)
	}
	genTLSCertificate()
}

func setup(mode string) {
	if mode == "" {
		mode = modeIP
	}

	client := newEC2Client()
	var instanceCount int32 = ec2InstanceCount
	if instanceCount == 1 {
		log.Printf("Creating %d instance...", instanceCount)
	} else {
		log.Printf("Creating %d instances...", instanceCount)
	}
	res, err := client.RunInstances(
		context.TODO(),
		&ec2.RunInstancesInput{
			ImageId:          aws.String(ec2ImageId),
			InstanceType:     ec2InstanceType,
			KeyName:          aws.String(os.Getenv(envSSH_ID)),
			MinCount:         &instanceCount,
			MaxCount:         &instanceCount,
			SecurityGroupIds: []string{os.Getenv(envAWS_SECURITY_GROUP_ID)},
			SubnetId:         aws.String(os.Getenv(envAWS_SUBNET_ID)),
		},
	)
	if err != nil {
		log.Fatalf("RunInstances failed: %v", err)
	}

	instances := map[string]string{}

	for _, i := range res.Instances {
		instances[*i.InstanceId] = ""
		if len(i.NetworkInterfaces) != 1 {
			log.Fatalf("Unexpected network interface configuration: %s", *i.InstanceId)
		}
		switch mode {
		case modeIP:
			_, err = client.ModifyInstanceAttribute(
				context.TODO(),
				&ec2.ModifyInstanceAttributeInput{
					InstanceId: i.InstanceId,
					SourceDestCheck: &types.AttributeBooleanValue{
						Value: aws.Bool(false),
					},
				},
			)
			if err != nil {
				log.Fatalf("ModifyInstanceAttribute failed: %v", err)
			}
		case modeSCION:
			var addressCount int32 = ec2InstancePrivateIpAddressCount - 1
			_, err = client.AssignPrivateIpAddresses(
				context.TODO(),
				&ec2.AssignPrivateIpAddressesInput{
					NetworkInterfaceId:             i.NetworkInterfaces[0].NetworkInterfaceId,
					SecondaryPrivateIpAddressCount: &addressCount,
				},
			)
			if err != nil {
				log.Fatalf("AssignPrivateIpAddresses failed: %v", err)
			}
		}
		_, err = client.CreateTags(
			context.TODO(),
			&ec2.CreateTagsInput{
				Resources: []string{*i.InstanceId},
				Tags: []types.Tag{
					{
						Key:   aws.String("Name"),
						Value: aws.String(ec2InstanceNamePrefix + mode),
					},
				},
			},
		)
		if err != nil {
			log.Fatalf("CreateTags failed: %v", err)
		}
	}

	if len(instances) != ec2InstanceCount {
		log.Fatalf("setup failed")
	}

	services := testnetServices[mode]
	data := map[string]string{}

	n := 0
	s := 0
	for i := 0; n < ec2InstanceCount && i < 60; i++ {
		res, err := client.DescribeInstances(
			context.TODO(),
			&ec2.DescribeInstancesInput{},
		)
		if err != nil {
			log.Fatalf("DescribeInstances failed: %v", err)
		}
		for _, r := range res.Reservations {
			for _, i := range r.Instances {
				if i.PublicIpAddress != nil {
					if _, ok := instances[*i.InstanceId]; ok {
						if instances[*i.InstanceId] != *i.PublicIpAddress {
							instances[*i.InstanceId] = *i.PublicIpAddress
							if s != len(services) {
								data[*i.InstanceId] = services[s]
								_, err = client.CreateTags(
									context.TODO(),
									&ec2.CreateTagsInput{
										Resources: []string{*i.InstanceId},
										Tags: []types.Tag{
											{
												Key:   aws.String("Role"),
												Value: aws.String(services[s]),
											},
										},
									},
								)
								if err != nil {
									log.Fatalf("CreateTags failed: %v", err)
								}
								for _, ni := range i.NetworkInterfaces {
									for k, a := range ni.PrivateIpAddresses {
										if k == 0 && !*a.Primary {
											panic("TODO")
										}
										t := services[s] + "_IP_" + strconv.Itoa(k)
										data[t] = *a.PrivateIpAddress
									}
								}
								s++
							}
							n++
						}
					}
				}
			}
		}
		time.Sleep(1 * time.Second)
	}

	if n != ec2InstanceCount {
		log.Fatalf("setup failed")
	}

	if mode == modeSCION {
		genCryptoMaterial()
		defer delCryptoMaterial()
	}

	var wg sync.WaitGroup
	for instanceId, instanceAddr := range instances {
		wg.Add(1)
		go setupInstance(&wg, instanceId, instanceAddr, mode, data)
	}
	wg.Wait()
}

func plotOffsetMeasurements(mark0, mark1 time.Duration) {
	f0, err := os.Open("./logs/offsets.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer f0.Close()

	r := csv.NewReader(f0)
	recs, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	t0, err := time.Parse(time.RFC3339, recs[0][0])
	if err != nil {
		log.Fatal(err)
	}

	minOff := math.Inf(1)
	maxOff := math.Inf(-1)

	data := make(plotter.XYs, len(recs))
	for i, rec := range recs {
		t, err := time.Parse(time.RFC3339, rec[0])
		if err != nil {
			log.Fatal(err)
		}
		off, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			log.Fatal(err)
		}
		minOff = math.Min(minOff, off)
		maxOff = math.Max(maxOff, off)
		data[i].X = float64(t.Unix() - t0.Unix())
		data[i].Y = off
	}

	p := plot.New()
	p.X.Label.Text = "Time [s]"
	p.X.Label.Padding = vg.Points(5)
	p.Y.Label.Text = "Offset [s]"
	p.Y.Label.Padding = vg.Points(5)
	p.Y.Max = maxOff
	p.Y.Min = minOff

	p.Add(plotter.NewGrid())

	line, err := plotter.NewLine(data)
	if err != nil {
		log.Panic(err)
	}
	p.Add(line)

	if mark0 >= 0 {
		rMarker, err := plotter.NewLine(plotter.XYs{
			plotter.XY{X: mark0.Seconds(), Y: p.Y.Min},
			plotter.XY{X: mark0.Seconds(), Y: p.Y.Max},
		})
		if err != nil {
			log.Panic(err)
		}
		rMarker.Width = vg.Points(2)
		rMarker.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
		rMarker.Color = color.RGBA{R: 255, A: 255}
		p.Add(rMarker)
	}

	if mark1 >= 0 {
		gMarker, err := plotter.NewLine(plotter.XYs{
			plotter.XY{X: mark1.Seconds(), Y: p.Y.Min},
			plotter.XY{X: mark1.Seconds(), Y: p.Y.Max},
		})
		if err != nil {
			log.Panic(err)
		}
		gMarker.Width = vg.Points(2)
		gMarker.Dashes = []vg.Length{vg.Points(2), vg.Points(2)}
		gMarker.Color = color.RGBA{B: 255, A: 255}
		p.Add(gMarker)
	}

	c := vgpdf.New(8.5*vg.Inch, 3*vg.Inch)
	c.EmbedFonts(true)
	dc := draw.New(c)
	dc = draw.Crop(dc, 1*vg.Millimeter, -1*vg.Millimeter, 1*vg.Millimeter, -1*vg.Millimeter)

	p.Draw(dc)

	f1, err := os.Create("./logs/offsets.pdf")
	if err != nil {
		log.Fatal(err)
	}
	defer f1.Close()

	_, err = c.WriteTo(f1)
	if err != nil {
		log.Fatal(err)
	}
}

func runAttack(instanceId, instanceAddr, mode, targetAddr string) {
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddr, err)
		return
	}
	defer sshClient.Close()
	cmd := strings.ReplaceAll(runAttackCommand[mode], "$TARGET_IP", targetAddr)
	runCommand(sshClient, instanceId, cmd)
}

func startOffsetMeasurements(wg *sync.WaitGroup, instanceAddr, mode, referenceAddr string) (
	*ssh.Client, *ssh.Session, *os.File, error) {
	sshClient, err := dialSSH(instanceAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	sshSession, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		return nil, nil, nil, err
	}
	logFile, err := createLogFile("offsets.csv")
	if err != nil {
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}
	sessStdout, err := sshSession.StdoutPipe()
	if err != nil {
		logFile.Close()
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(logFile, sessStdout)
	}()
	sessStderr, err := sshSession.StderrPipe()
	if err != nil {
		logFile.Close()
		sshSession.Close()
		sshClient.Close()
		return nil, nil, nil, err
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(logFile, sessStderr)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		cmd := strings.ReplaceAll(measureOffsetsCommand[mode], "$REFC_IP", referenceAddr)
		err = sshSession.Run(cmd)
		if err != nil {
			var exitError *ssh.ExitError
			if !errors.As(err, &exitError) || exitError.ExitStatus() != 143 {
				log.Printf("Failed to measure offsets on instance %s: %v", instanceAddr, err)
			}
		}
	}()
	return sshClient, sshSession, logFile, nil
}

func run(mode string) {
	if mode == "" {
		mode = modeIP
	}

	instanceIds := map[string]string{}
	instanceAddrs := map[string]string{}

	client := newEC2Client()
	res, err := client.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{},
	)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range res.Reservations {
		for _, i := range r.Instances {
			if *i.State.Code == ec2InstanceStateRunning {
				for _, t := range i.Tags {
					if *t.Key == "Name" &&
						*t.Value == ec2InstanceNamePrefix+mode {
						for _, tt := range i.Tags {
							if *tt.Key == "Role" {
								switch *tt.Value {
								case svcAS_A_TS, svcAS_B_TS, svcAS_C_INFRA, svcLGC:
									if i.InstanceId != nil {
										instanceIds[*tt.Value] = *i.InstanceId
									}
									if i.PublicIpAddress != nil {
										instanceAddrs[*tt.Value] = *i.PublicIpAddress
									}
								case svcLGS, svcREFC:
									if i.InstanceId != nil {
										instanceIds[*tt.Value] = *i.InstanceId
									}
									if i.PrivateIpAddress != nil {
										instanceAddrs[*tt.Value] = *i.PrivateIpAddress
									}
								}
							}
						}
					}
				}
			}
		}
	}

	sshClientAS_A_TS, err := dialSSH(instanceAddrs[svcAS_A_TS])
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddrs[svcAS_A_TS], err)
		return
	}
	defer sshClientAS_A_TS.Close()
	sshClientAS_B_TS, err := dialSSH(instanceAddrs[svcAS_B_TS])
	if err != nil {
		log.Printf("Failed to connect to instance %s: %v", instanceAddrs[svcAS_B_TS], err)
		return
	}
	defer sshClientAS_B_TS.Close()

	var referenceAddr string
	switch mode {
	case modeIP:
		referenceAddr = ec2ReferenceClockAddr
	case modeSCION:
		referenceAddr = instanceAddrs[svcREFC]
	}

	var wg sync.WaitGroup
	sshClient, sshSession, logFile, err := startOffsetMeasurements(&wg, instanceAddrs[svcAS_B_TS], mode, referenceAddr)
	if err != nil {
		log.Fatalf("startOffsetMeasurements failed: %v", err)
	}

	t0 := time.Now()

	log.Printf("Preparing 1st attack [ca. %ds]...", attackPreparation[mode]/time.Second)
	runCommands(sshClientAS_A_TS, instanceIds[svcAS_A_TS], instanceAddrs[svcAS_A_TS],
		setDSCPValue0Commands[mode][svcAS_A_TS])
	runCommands(sshClientAS_B_TS, instanceIds[svcAS_B_TS], instanceAddrs[svcAS_B_TS],
		setDSCPValue0Commands[mode][svcAS_B_TS])
	time.Sleep(attackPreparation[mode])

	mark0 := time.Since(t0)

	log.Printf("Running 1st attack [ca. %ds]...", attackDuration[mode]/time.Second)
	for i := 0; i != attackCount[mode]; i++ {
		switch mode {
		case modeIP:
			go runAttack(instanceIds[svcLGC], instanceAddrs[svcLGC], mode, instanceAddrs[svcLGS])
		case modeSCION:
			go runAttack(instanceIds[svcAS_C_INFRA], instanceAddrs[svcAS_C_INFRA], mode, attackTargetSCION)
		}
	}
	time.Sleep(attackDuration[mode])

	log.Printf("Preparing 2nd attack [ca. %ds]...", attackPreparation[mode]/time.Second)
	runCommands(sshClientAS_A_TS, instanceIds[svcAS_A_TS], instanceAddrs[svcAS_A_TS],
		setDSCPValue46Commands[mode][svcAS_A_TS])
	runCommands(sshClientAS_B_TS, instanceIds[svcAS_B_TS], instanceAddrs[svcAS_B_TS],
		setDSCPValue46Commands[mode][svcAS_B_TS])
	time.Sleep(attackPreparation[mode])

	mark1 := time.Since(t0)

	log.Printf("Running 2nd attack [ca. %ds]...", attackDuration[mode]/time.Second)
	for i := 0; i != attackCount[mode]; i++ {
		switch mode {
		case modeIP:
			go runAttack(instanceIds[svcLGC], instanceAddrs[svcLGC], mode, instanceAddrs[svcLGS])
		case modeSCION:
			go runAttack(instanceIds[svcAS_C_INFRA], instanceAddrs[svcAS_C_INFRA], mode, attackTargetSCION)
		}
	}
	time.Sleep(attackDuration[mode])

	log.Print("Finishing test run...")
	err = sshSession.Signal(ssh.SIGTERM)
	if err == nil {
		wg.Wait()
	}
	sshSession.Close()
	sshClient.Close()
	logFile.Close()

	plotOffsetMeasurements(mark0, mark1)
}

func teardown(mode string) {
	client := newEC2Client()
	var instanceIds []string
	res, err := client.DescribeInstances(
		context.TODO(),
		&ec2.DescribeInstancesInput{},
	)
	if err != nil {
		log.Fatalf("DescribeInstances failed: %v", err)
	}
	for _, r := range res.Reservations {
		for _, i := range r.Instances {
			if *i.State.Code != ec2InstanceStateTerminated {
				for _, t := range i.Tags {
					if *t.Key == "Name" && (*t.Value == ec2InstanceNamePrefix+mode ||
						mode == "" && strings.HasPrefix(*t.Value, ec2InstanceNamePrefix)) {
						instanceIds = append(instanceIds, *i.InstanceId)
					}
				}
			}
		}
	}
	if len(instanceIds) != 0 {
		_, err = client.TerminateInstances(
			context.TODO(),
			&ec2.TerminateInstancesInput{
				InstanceIds: instanceIds,
			},
		)
		if err != nil {
			log.Fatalf("TerminateInstances failed: %v", err)
		}
	}
}

func exitWithUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  list     List available instances")
	fmt.Fprintln(os.Stderr, "  setup    Set up the environment")
	fmt.Fprintln(os.Stderr, "  run      Run the evaluation")
	fmt.Fprintln(os.Stderr, "  teardown Clean up the environment")
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintln(os.Stderr, "  -mode string  Mode to operate in (must be 'ip' or 'scion')")
	os.Exit(1)
}

func validateMode(mode string) {
	switch mode {
	case "", modeIP, modeSCION:
		return
	default:
		exitWithUsage()
	}
}

func main() {
	listFlags := flag.NewFlagSet("list", flag.ExitOnError)
	setupFlags := flag.NewFlagSet("setup", flag.ExitOnError)
	runFlags := flag.NewFlagSet("run", flag.ExitOnError)
	teardownFlags := flag.NewFlagSet("teardown", flag.ExitOnError)

	const modeUsage = "Mode to operate in (must be 'ip' or 'scion')"
	var mode string
	listFlags.StringVar(&mode, "mode", "", modeUsage)
	setupFlags.StringVar(&mode, "mode", "", modeUsage)
	runFlags.StringVar(&mode, "mode", "", modeUsage)
	teardownFlags.StringVar(&mode, "mode", "", modeUsage)

	if len(os.Args) < 2 {
		exitWithUsage()
	}

	switch os.Args[1] {
	case listFlags.Name():
		err := listFlags.Parse(os.Args[2:])
		if err != nil || listFlags.NArg() != 0 {
			exitWithUsage()
		}
		validateMode(mode)
		listInstances(mode)
	case setupFlags.Name():
		err := setupFlags.Parse(os.Args[2:])
		if err != nil || setupFlags.NArg() != 0 {
			exitWithUsage()
		}
		validateMode(mode)
		setup(mode)
	case runFlags.Name():
		err := runFlags.Parse(os.Args[2:])
		if err != nil || runFlags.NArg() != 0 {
			exitWithUsage()
		}
		validateMode(mode)
		run(mode)
	case teardownFlags.Name():
		err := teardownFlags.Parse(os.Args[2:])
		if err != nil || teardownFlags.NArg() != 0 {
			exitWithUsage()
		}
		validateMode(mode)
		teardown(mode)
	default:
		exitWithUsage()
	}
}
