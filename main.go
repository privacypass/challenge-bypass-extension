package main

import (
	"time"

	"./beacon"
)

func main() {
	//creates and starts a new Beacon that print a new commitement every 10 seconds
	//the beacon is stopped after 25 sec, meaning after 3 outputs
	b := beacon.NewBeacon("localhost")
	period := time.Duration(10) * time.Second
	go b.Loop(period)
	time.Sleep(time.Duration(25) * time.Second)
	b.Stop()
}
