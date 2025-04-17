package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/glaslos/tlsh"
)

const (
	csvURL = "https://raw.githubusercontent.com/Magonia-Research/CelesTLSH-Hashes/HEAD/all_attack_tools_hashes.csv"
)

// HashRecord represents a row in the TLSH hash database
type HashRecord struct {
	RepoName   string
	FileName   string
	Version    string
	TLSHHash   string
	SHA256Hash string
	Imphash    string
	DateAdded  string
	Intel      string
	Distance   int
}

// Config holds the application configuration
type Config struct {
	Mode      string
	FilePath  string
	Hash1     string
	Hash2     string
	DbPath    string
	Quiet     bool
	OutputCSV bool
}

func main() {
	// Parse command-line flags and determine operation mode
	config := parseFlags()

	// Execute the appropriate operation based on the mode
	err := execute(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseFlags parses command-line flags and determines the operation mode
func parseFlags() Config {
	// Define configuration
	var config Config

	// Define CLI flags
	hashFlag := flag.Bool("hash", false, "Calculate TLSH hash of a file")
	hashShortFlag := flag.Bool("h", false, "Calculate TLSH hash of a file (shorthand)")

	distanceFlag := flag.Bool("distance", false, "Calculate distance between two TLSH hashes")
	distanceShortFlag := flag.Bool("d", false, "Calculate distance between two TLSH hashes (shorthand)")

	downloadFlag := flag.Bool("download", false, "Download the CSV database of TLSH hashes")
	downloadShortFlag := flag.Bool("dl", false, "Download the CSV database of TLSH hashes (shorthand)")

	checkFlag := flag.Bool("check", false, "Check a TLSH hash against the database")
	checkShortFlag := flag.Bool("c", false, "Check a TLSH hash against the database (shorthand)")

	dbPathFlag := flag.String("db", "tlsh_hashes.csv", "Path to the CSV database file")
	quietFlag := flag.Bool("quiet", false, "Output only the hash or distance value")
	csvOutputFlag := flag.Bool("csv", false, "Output results in CSV format (only applies to check mode)")

	// Parse flags
	flag.Parse()

	// Process remaining arguments
	args := flag.Args()

	// Set configuration based on flags
	config.DbPath = *dbPathFlag
	config.Quiet = *quietFlag
	config.OutputCSV = *csvOutputFlag

	// Determine mode of operation
	switch {
	case *hashFlag || *hashShortFlag:
		config.Mode = "hash"
		if len(args) < 1 {
			printUsage("No file path provided for hash calculation")
			os.Exit(1)
		}
		config.FilePath = args[0]

	case *distanceFlag || *distanceShortFlag:
		config.Mode = "distance"
		if len(args) < 2 {
			printUsage("Two TLSH hashes are required for distance calculation")
			os.Exit(1)
		}
		config.Hash1 = args[0]
		config.Hash2 = args[1]

	case *downloadFlag || *downloadShortFlag:
		config.Mode = "download"

	case *checkFlag || *checkShortFlag:
		config.Mode = "check"
		if len(args) < 1 {
			printUsage("No TLSH hash provided for checking against the database")
			os.Exit(1)
		}
		config.Hash1 = args[0]

	default:
		// If no flag is specified, print usage
		printUsage("")
		os.Exit(0)
	}

	return config
}

// execute performs the operation specified by the configuration
func execute(config Config) error {
	switch config.Mode {
	case "hash":
		return executeHash(config)
	case "distance":
		return executeDistance(config)
	case "download":
		return executeDownload(config)
	case "check":
		return executeCheck(config)
	default:
		return fmt.Errorf("unknown mode: %s", config.Mode)
	}
}

// executeHash calculates and outputs the TLSH hash of a file
func executeHash(config Config) error {
	hash, err := calculateTLSHHash(config.FilePath)
	if err != nil {
		return fmt.Errorf("failed to calculate TLSH hash: %v", err)
	}

	if config.Quiet {
		fmt.Println(hash)
	} else {
		fmt.Printf("TLSH hash of %s: %s\n", config.FilePath, hash)
	}

	return nil
}

// executeDistance calculates and outputs the distance between two TLSH hashes
func executeDistance(config Config) error {
	distance, err := calculateTLSHDistance(config.Hash1, config.Hash2)
	if err != nil {
		return fmt.Errorf("failed to calculate TLSH distance: %v", err)
	}

	if config.Quiet {
		fmt.Println(distance)
	} else {
		fmt.Printf("Distance between hashes: %d\n", distance)
	}

	return nil
}

// executeDownload downloads the CSV database of TLSH hashes
func executeDownload(config Config) error {
	err := downloadCSVDatabase(config.DbPath)
	if err != nil {
		return fmt.Errorf("failed to download CSV database: %v", err)
	}

	if !config.Quiet {
		fmt.Printf("CSV database downloaded to %s\n", config.DbPath)
	}

	return nil
}

// executeCheck checks a TLSH hash against the database
func executeCheck(config Config) error {
	// Check if the database exists
	if _, err := os.Stat(config.DbPath); os.IsNotExist(err) {
		return fmt.Errorf("database file %s does not exist; download it first with --download", config.DbPath)
	}

	match, err := checkTLSHAgainstDatabase(config.Hash1, config.DbPath)
	if err != nil {
		return fmt.Errorf("failed to check TLSH against database: %v", err)
	}

	if match == nil {
		if !config.Quiet {
			fmt.Println("No matches found in the database")
		}
		return nil
	}

	// Output the best match
	if config.OutputCSV {
		fmt.Printf("%s,%s,%s,%s,%d\n", match.RepoName, match.FileName, match.Version, match.SHA256Hash, match.Distance)
	} else if config.Quiet {
		fmt.Println(match.SHA256Hash)
	} else {
		fmt.Println("Best match found:")
		fmt.Printf("  Tool: %s\n", match.RepoName)
		fmt.Printf("  File: %s\n", match.FileName)
		fmt.Printf("  SHA256: %s\n", match.SHA256Hash)
		fmt.Printf("  Distance: %d\n", match.Distance)
	}

	return nil
}

// calculateTLSHHash calculates the TLSH hash of a file
func calculateTLSHHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	hash, err := tlsh.HashBytes(data)
	if err != nil {
		return "", fmt.Errorf("error calculating TLSH hash: %v", err)
	}

	return hash.String(), nil
}

// calculateTLSHDistance calculates the distance between two TLSH hashes
func calculateTLSHDistance(hash1, hash2 string) (int, error) {
	t1, err := tlsh.ParseStringToTlsh(hash1)
	if err != nil {
		return -1, fmt.Errorf("error parsing first hash: %v", err)
	}

	t2, err := tlsh.ParseStringToTlsh(hash2)
	if err != nil {
		return -1, fmt.Errorf("error parsing second hash: %v", err)
	}

	return t1.Diff(t2), nil
}

// downloadCSVDatabase downloads the CSV database of TLSH hashes
func downloadCSVDatabase(outputPath string) error {
	// Create the directory path if it doesn't exist
	dirPath := filepath.Dir(outputPath)
	if dirPath != "." {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("error creating directory: %v", err)
		}
	}

	// Create a HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Download the CSV file
	resp, err := client.Get(csvURL)
	if err != nil {
		return fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create output file
	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer func() {
		cerr := out.Close()
		if err == nil && cerr != nil {
			err = cerr
		}
	}()

	// Copy data to output file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("error saving data to file: %v", err)
	}

	return nil
}

// checkTLSHAgainstDatabase checks a TLSH hash against the database
func checkTLSHAgainstDatabase(hashToCheck, dbPath string) (*HashRecord, error) {
	// Open the CSV file
	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("error opening database file: %v", err)
	}
	defer file.Close()

	// Parse the CSV
	reader := csv.NewReader(file)

	// Read and validate header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV header: %v", err)
	}

	// Validate header structure (optional but recommended)
	expectedColumns := 8
	if len(header) < expectedColumns {
		return nil, fmt.Errorf("CSV header has fewer columns than expected: got %d, want at least %d", len(header), expectedColumns)
	}

	// Parse TLSH hash to check
	hashObj, err := tlsh.ParseStringToTlsh(hashToCheck)
	if err != nil {
		return nil, fmt.Errorf("error parsing input hash: %v", err)
	}

	var matches []HashRecord

	// Process each record
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV record: %v", err)
		}

		// Skip invalid records
		if len(record) < 8 {
			continue
		}

		tlshHashStr := record[3]
		if tlshHashStr == "" || tlshHashStr == "N/A" {
			continue
		}

		// Parse the TLSH hash from the database
		dbHashObj, err := tlsh.ParseStringToTlsh(tlshHashStr)
		if err != nil {
			continue
		}

		// Calculate distance
		distance := hashObj.Diff(dbHashObj)

		// Add to matches
		matches = append(matches, HashRecord{
			RepoName:   record[0],
			FileName:   record[1],
			Version:    record[2],
			TLSHHash:   record[3],
			SHA256Hash: record[4],
			Imphash:    record[5],
			DateAdded:  record[6],
			Intel:      record[7],
			Distance:   distance,
		})
	}

	if len(matches) == 0 {
		return nil, nil
	}

	// Sort by distance (ascending)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Distance < matches[j].Distance
	})

	// Return the match with the lowest distance
	return &matches[0], nil
}

// printUsage prints the usage information
func printUsage(errorMsg string) {
	if errorMsg != "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n\n", errorMsg)
	}

	fmt.Println("TLSH CLI Tool - Calculate and compare TLSH hashes")
	fmt.Println("\nUsage:")
	fmt.Println("  Calculate TLSH hash of a file:")
	fmt.Println("    tlsh-cli -h <file_path>")
	fmt.Println("    tlsh-cli --hash <file_path>")
	fmt.Println("\n  Calculate distance between two TLSH hashes:")
	fmt.Println("    tlsh-cli -d <hash1> <hash2>")
	fmt.Println("    tlsh-cli --distance <hash1> <hash2>")
	fmt.Println("\n  Download the CSV database of TLSH hashes:")
	fmt.Println("    tlsh-cli -dl [--db <output_path>]")
	fmt.Println("    tlsh-cli --download [--db <output_path>]")
	fmt.Println("\n  Check a TLSH hash against the database:")
	fmt.Println("    tlsh-cli -c <hash> [--db <database_path>]")
	fmt.Println("    tlsh-cli --check <hash> [--db <database_path>]")
	fmt.Println("\nOptions:")
	fmt.Println("  --quiet        Output only the hash, distance, or SHA256 value")
	fmt.Println("  --csv          Output check results in CSV format")
	fmt.Println("  --db <path>    Specify the database path (default: tlsh_hashes.csv)")
}
