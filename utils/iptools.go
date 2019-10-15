package iptools

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os/exec"
	"time"
)

var err error

type BlockedIP struct {
	IpAddress string
	LastSeen  time.Time
	Banned    bool
}

type BanConf struct {
	LogPath  string `yaml:"logpath"`
	Interval int    `yaml:"secondinterval"`
	MaxCount int    `yaml:"maxipcount"`
}

// Count for IP in array for duplicate
func CountIP(maxCount int, myip string, ad *[]BlockedIP, interval int) bool {
	myList := &ad
	var allTime []time.Time
	localCount := 0

	for _, v := range **myList {
		if v.IpAddress == myip {
			localCount++
			allTime = append(allTime, v.LastSeen)
			if localCount >= maxCount {
				timeSub := allTime[len(allTime)-1].Sub(allTime[0])
				if timeSub < time.Second*time.Duration(interval) {
					return true
				} else {
					return false
				}
			} else {
				continue
			}
		}
	}
	return false
}

// Block IP with firewall
func BlockIP(ip string) {
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	err = cmd.Run()
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Printf("Blocked IP: %v\n", ip)
	}
}

// Check for a new log filename of SoftetherVPN
func CheckFileName(filename string, cnf BanConf, f chan<- string) {
	for {
		newFilename := fmt.Sprintf("%v/%v", cnf.LogPath, LogNameFormat(time.Now()))
		if newFilename != filename {
			log.Println("A new logfile", newFilename)
			f <- newFilename
			return
		}
	}
}

// Read config from file
func Config(cp string) BanConf {
	t := BanConf{}
	f, err := ioutil.ReadFile(cp)
	if err != nil {
		log.Fatalln(err)
	}

	err = yaml.Unmarshal(f, &t)
	if err != nil {
		log.Fatalln(err)
	}
	return t
}

// Format of name for SoftetherVPN
func LogNameFormat(t time.Time) string {
	return t.Format("vpn_20060102.log")
}

// Check IP for already blocked
func CheckInBlockList(s string, ips []BlockedIP) bool {
	for _, v := range ips {
		if s == v.IpAddress {
			return true
		}
	}
	return false
}
