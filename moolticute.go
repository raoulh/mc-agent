package main

//Moolticute websocket connection

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"git.sr.ht/~oliverpool/go-moolticute"
)

//We store an array of bytes to the device
type McBinKeys [][]byte

func McLoadKeys() (*McBinKeys, error) {
	resp, err := moolticute.MakeRequest(*mcUrl, "get_data_node", moolticute.Data{
		Service: "Moolticute SSH Keys",
	}, moolticute.HandleOtherMsg(printProgressForMoolticute))
	if err != nil {
		var errResponse moolticute.ResponseError
		if errors.As(err, &errResponse) {
			// everything went fine, but keys are not present
			// or the user declined access
			// create blank keys
			return new(McBinKeys), nil
		}
		return nil, fmt.Errorf("could not get data: %w", err)
	}

	// decode Base64+gob encoded data from device
	bdec, err := base64.StdEncoding.DecodeString(resp.NodeData)
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode data: %w", err)
	}

	keys := new(McBinKeys)
	buffer := bytes.NewBuffer(bdec)
	binDec := gob.NewDecoder(buffer)
	err = binDec.Decode(keys)
	if err != nil {
		return nil, fmt.Errorf("could not decode encoding/gob: %w", err)
	}

	return keys, nil
}

func McSetKeys(keys *McBinKeys) error {
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(keys); err != nil {
		return fmt.Errorf("could not encode with encoding/gob: %v", err)
	}

	resp, err := moolticute.MakeRequest(*mcUrl, "set_data_node", moolticute.Data{
		Service:  "Moolticute SSH Keys",
		NodeData: base64.StdEncoding.EncodeToString(buffer.Bytes()),
	}, moolticute.HandleOtherMsg(printProgressForMoolticute))
	if err != nil {
		return fmt.Errorf("could not set data: %#v %w", resp, err)
	}
	return nil
}

// used by moolticute for loading keys into gui
func printProgressForMoolticute(msg string, data json.RawMessage) error {
	if (msg == "progress" || msg == "progress_detailed") && *outputProgress {
		json.NewEncoder(os.Stdout).Encode(struct {
			Msg  string          `json:"msg"`
			Data json.RawMessage `json:"data"`
		}{
			Msg:  msg,
			Data: data,
		})
		os.Stdout.Sync()
	}
	return nil
}
