package main

import (
	proofsystem "OPPID/pkg/nizk/hash"
	"fmt"
	"os"
	"time"
)

func getFileSizeInMB(filePath string) (float64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}

	fileSizeBytes := fileInfo.Size()

	sizeMB := float64(fileSizeBytes) / (1024 * 1024)
	return sizeMB, nil
}

func deleteFile(filePath string) {
	err := os.Remove(filePath)
	if err != nil {
		fmt.Printf("Error deleting file: %v\n", err)
	}
}

func main() {
	pp, err := proofsystem.Setup()
	if err != nil {
		fmt.Printf("Error generating hash proof system: %v\n", err)
		return
	}
	startTime := time.Now()
	_, _, err = pp.KeyGen()
	if err != nil {
		fmt.Printf("Error generating keys: %v\n", err)
		return
	}
	elapsedTime := time.Since(startTime)

	circuitSizeMB, err := getFileSizeInMB(proofsystem.CircuitFileName)
	if err != nil {
		fmt.Printf("Error getting circuit file size: %v\n", err)
		return
	}
	provingKeySizeMB, err := getFileSizeInMB(proofsystem.PkFileName)
	if err != nil {
		fmt.Printf("Error getting proving key file size: %v\n", err)
		return
	}
	verificationKeySizeMB, err := getFileSizeInMB(proofsystem.VkFileName)
	if err != nil {
		fmt.Printf("Error getting verification key file size: %v\n", err)
		return
	}

	fmt.Printf("Number of constraints: %v\n", pp.CS.GetNbConstraints())
	fmt.Printf("KeyGen took: %.2f seconds\n", elapsedTime.Seconds())
	fmt.Printf("Circuit size MB: %v\n", circuitSizeMB)
	fmt.Printf("Proving key size MB: %v\n", provingKeySizeMB)
	fmt.Printf("Verification key size MB: %v\n", verificationKeySizeMB)

	deleteFile(proofsystem.CircuitFileName)
	deleteFile(proofsystem.PkFileName)
	deleteFile(proofsystem.VkFileName)
}
