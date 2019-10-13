package main

import (
	iptools "blockSpamers/utils"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/hpcloud/tail"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"time"
)

var t *tail.Tail
var ip string
var count int
var blockedIPS []iptools.BlockedIP
var regEXP = `(?P<time>^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d).+\((?P<ipaddr>[0-9]+(?:\.[0-9]+){3}).+channel is created`
var timeFormat = "2006-01-02 15:04:05"
var filename string
var checkFilename string

type BanConf struct {
	LogPath  string `yaml:"logpath"`
	Interval int    `yaml:"secondinterval"`
	MaxCount int    `yaml:"maxipcount"`
}

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

func checkInBlockList(s string, ips []iptools.BlockedIP) bool {
	for _, v := range ips {
		if s == v.IpAddress {
			return true
		}
	}
	return false
}

func logNameFormat(t time.Time) string {
	return t.Format("vpn_20060102.log")
}

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

	cnf := Config(*configPath)
	maxCNT := cnf.MaxCount
	bullShitBingo := make([]iptools.BlockedIP, maxCNT)

	l, err := os.OpenFile("/var/log/blocked.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(l)

	for {
		filename = fmt.Sprintf("%v/%v", cnf.LogPath, logNameFormat(time.Now()))
		t, err = tail.TailFile(filename, tail.Config{Follow: true, ReOpen: true})
		if err != nil {
			log.Fatalln(err)
		}
		for line := range t.Lines {
			checkFilename = fmt.Sprintf("%v/%v", cnf.LogPath, logNameFormat(time.Now()))
			if checkFilename != filename {
				break
			}
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
					if !checkInBlockList(ip, blockedIPS) {
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
