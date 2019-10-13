package iptools

import (
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

func BlockIP(ip string) {
	cmd := exec.Command("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	err = cmd.Run()
	if err != nil {
		log.Fatalln(err)
	} else {
		log.Printf("Blocked IP: %v\n", ip)
	}
}
