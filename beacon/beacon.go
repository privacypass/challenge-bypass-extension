/*
beacon.go hold the core of the beacon code.
Every t seconds, it picks a point on the curve P-256 and adds it to a
JSON storing all its commitements by using bjson.go.
For now the compatibilty with the existing file commitments-p256.json
is not implemented yet.
**This code is a draft of automatization of the process of generating
the commitements.**
*/

package beacon

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"math/big"
	"sync"
	"time"
)

var curve = elliptic.P256()
var G = BasePoint()

//BasePoint return G
func BasePoint() *Point {
	one := make([]byte, 32)
	one[31] = 1
	x, y := curve.ScalarBaseMult(one)
	return &Point{x, y}
}

// Point holds the coordinates of a point
type Point struct {
	x *big.Int
	y *big.Int
}

// Beacon holds info related to a specific beacon
type Beacon struct {
	ticker *time.Ticker
	round  uint64
	close  chan bool
	sync.Mutex
	// should add here the public/private key pair
	commitsFile string
}

// NewBeacon creates a Beacon
func NewBeacon(address string) *Beacon {
	commitsFile := "beacon/commits.json"
	skeleton := `{"CF":{}, "HC":{}}`
	err := ioutil.WriteFile(commitsFile, []byte(skeleton), 0777)
	if err != nil {
		print("could not create file")
	}

	return &Beacon{
		close:       make(chan bool),
		round:       0,
		commitsFile: commitsFile,
	}
}

// Loop makes a beacon call run every x seconds
func (b *Beacon) Loop(period time.Duration) {
	b.Lock()
	b.ticker = time.NewTicker(period)
	b.Unlock()

	var goToNextRound = true
	var currentRoundFinished bool

	//this channel is used by run to notify loop when done
	doneCh := make(chan uint64)
	//this channel is used by loop to stop run if needed
	closingCh := make(chan bool)

	for {

		if goToNextRound {
			//tell run to stop
			close(closingCh)
			closingCh = make(chan bool)
			round := b.nextRound()
			go b.run(round, doneCh, closingCh)
			goToNextRound = false
			currentRoundFinished = false
		}

		select {
		//beacon was stopped
		case <-b.close:
			goToNextRound = false
			close(closingCh)
			close(doneCh)
			return

		//period is over
		case <-b.ticker.C:
			if !currentRoundFinished {
				close(closingCh)
			}
			goToNextRound = true
			continue

		//run is done
		case roundCh := <-doneCh:
			if roundCh != b.round {
				continue
			}
			currentRoundFinished = true
		}
	}
}

// nextRound increase the round counter
func (b *Beacon) nextRound() uint64 {
	b.Lock()
	b.round++
	b.Unlock()
	return b.round
}

// run creates committements and prints them
func (b *Beacon) run(round uint64, doneCh chan uint64, closingCh chan bool) {
	select {
	case <-closingCh:
		return
	default:
		k, _ := rand.Int(rand.Reader, curve.Params().N)
		x, y := curve.ScalarBaseMult(k.Bytes())
		H := &Point{
			x: x,
			y: y,
		}
		fmt.Printf("Round: %d\n", round)
		fmt.Printf("G: (%v, %v)\n", G.x, G.y)
		fmt.Printf("H: (%v, %v)\n", H.x, H.y)
		fmt.Printf("k: %v\n", k)
		if err := b.AddCommit(k, H); err != nil {
			print(err)
		}
		//TODO: Sign the file after adding new commits
		doneCh <- round
	}
}

// Stop stops the beacon
func (b *Beacon) Stop() {
	b.Lock()
	close(b.close)
	if b.ticker != nil {
		b.ticker.Stop()
	}
	b.Unlock()
	fmt.Printf("Beacon stopped after %d rounds \n", b.round)
}
