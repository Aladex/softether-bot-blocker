package main

import (
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/hpcloud/tail"
	"log"
	"os"
	"regexp"
	iptools "softether-bot-blocker/utils"
	"time"
)

var ip string
var count int
var blockedIPS []iptools.BlockedIP
var regEXP = `(?P<time>^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d).+\((?P<ipaddr>[0-9]+(?:\.[0-9]+){3}).+channel is created`
var timeFormat = "2006-01-02 15:04:05"
var filename string

func main() {
	parser := argparse.NewParser("print", "Binare that runs after TLS release")
	// Create string flag
	configPath := parser.String(
		"c",
		"config",
		&argparse.Options{
			Required: true,
			Help:     "command",
			Default:  "soft_reset",
		})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	cnf := iptools.Config(*configPath)
	maxCNT := cnf.MaxCount
	bullShitBingo := make([]iptools.BlockedIP, maxCNT)

	l, err := os.OpenFile("/var/log/blocked.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(l)
	filenameChan := make(chan string)

	for {
		filename = fmt.Sprintf("%v/%v", cnf.LogPath, iptools.LogNameFormat(time.Now()))
		t, err := tail.TailFile(filename, tail.Config{Follow: true, ReOpen: true, MustExist: true})
		if err != nil {
			log.Println("No log file", filename, ". Waiting for 1 minute")
			time.Sleep(time.Minute * 10)
			continue
		}

		go iptools.CheckFileName(filename, cnf, filenameChan)
		go func() {
			for {
				select {
				case name := <-filenameChan:
					log.Println("Received a new name for log:", name)
					t.Stop()
					return
				}
			}
		}()

		if err != nil {
			log.Fatalln(err)
		}
		for line := range t.Lines {

			re := regexp.MustCompile(regEXP)
			match := re.FindStringSubmatch(line.Text)
			if len(match) > 2 {
				ip = match[2]
				timeString := match[1]
				timeSeen, err := time.Parse(timeFormat, timeString)
				if err != nil {
					log.Fatalln(err)
				}
				if iptools.CountIP(maxCNT-1, ip, &bullShitBingo, cnf.Interval) {
					if !iptools.CheckInBlockList(ip, blockedIPS) {
						go iptools.BlockIP(ip)
						blockedIPS = append(blockedIPS, iptools.BlockedIP{
							IpAddress: ip,
							LastSeen:  timeSeen,
						})

					}
				}

				bullShitBingo[count] = iptools.BlockedIP{
					IpAddress: ip,
					LastSeen:  timeSeen,
				}
				count++
				if count >= len(bullShitBingo)-1 {
					count = 0
				}
			}
		}
	}
}
