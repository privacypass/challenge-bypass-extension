/*
This file is used by a beacon to modify the JSON file collecting its commitments
*/

package beacon

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
)

//JSONCommit hold one commit where the version is the round
type JSONCommit struct {
	Version struct {
		G string `json:"G"`
		H string `json:"H"`
	}
}

//JSONFile holds the commitments-p256.json file in dict format
type JSONFile struct {
	CF JSONCommit `json:"CF"`
	HC JSONCommit `json:"HC"`
}

// AddCommit adds the generated commitements to the json file of the beacon
// For now we cannot concatenate commits, so it overwrites it. TODO !
// Also need to dig in to understand the HC / CF commits differences
func (b *Beacon) AddCommit(k *big.Int, H *Point) error {
	//open file
	jsonFile, err := os.Open(b.commitsFile)
	if err != nil {
		print("could not load commit file")
	}
	defer jsonFile.Close()
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		print("err reding file")
	}
	//store it in dict
	res := JSONFile{}
	json.Unmarshal(byteValue, &res)
	//modify the json
	gstr := b.PointToString(G)
	hstr := b.PointToString(H)
	res.CF.Version.G, res.HC.Version.G = gstr, gstr
	res.CF.Version.H, res.HC.Version.H = hstr, hstr
	final := b.JSONFileToString(res)
	//write it back
	err = ioutil.WriteFile(b.commitsFile, []byte(final), 0777)
	if err != nil {
		print("Could not write the new commits")
	}
	return nil
}

// JSONFileToString corrects the version and return a string
func (b *Beacon) JSONFileToString(d JSONFile) string {
	version := strconv.Itoa(int(b.round))
	res2, _ := json.MarshalIndent(d, "", "    ")
	//for now we have only one commit at a time, this should change
	//when we modify the code to concatenate more TODO
	return strings.Replace(string(res2), "Version", version, 2)
}

// PointToString take a point and creates matching string to wite in JSON jsonFile
// TODO: compatibilty with existing JSON
func (b *Beacon) PointToString(p *Point) string {
	return fmt.Sprintf("%#v", p)
}
