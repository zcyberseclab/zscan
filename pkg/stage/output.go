package stage

import (
	"encoding/json"
	"fmt"
)

func PrintResults(nodes []Node) error {
	jsonData, err := json.MarshalIndent(struct {
		Nodes []Node `json:"nodes"`
	}{nodes}, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling results to JSON: %v", err)
	}

	fmt.Println(string(jsonData))

	return nil
}
