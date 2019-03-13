package main

import (
	"time"

	"./beacon"
)

func main() {
	id := int32(1)
	b := beacon.NewBeacon("localhost", id)
	period := time.Duration(5) * time.Second
	go b.Loop(period)
	time.Sleep(time.Duration(20) * time.Second)
	b.Stop()
}
