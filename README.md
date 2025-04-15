# CelesTLSH-CLI Tool

A command-line tool for calculating, comparing, and analyzing TLSH (Trend Micro Locality Sensitive Hash) values. This tool provides a streamlined interface for working with TLSH hashes, including functionality to check hashes against a known database of malware tools.

## What is TLSH?

TLSH (Trend Micro Locality Sensitive Hash) is a fuzzy matching algorithm that generates hash values which can be used for similarity comparisons. Similar files will have similar hash values, allowing for the detection of similar objects by comparing their hash values. Unlike cryptographic hashes like SHA-256, TLSH is designed to measure similarity rather than provide exact matching.

TLSH is particularly useful in:
- Malware analysis and classification
- Detecting variants of known malicious files
- Finding similar files in large datasets
- Identifying obfuscated or slightly modified files

## Features

- Calculate TLSH hash of any file
- Calculate distance between two TLSH hashes
- Download a centralized database of TLSH hashes from known attack tools
- Check TLSH hash against the database to find the closest match
- Multiple output formats (normal, quiet, and CSV)

## Installation

### Prerequisites

- Go 1.16 or later
- Internet connection (for downloading the hash database)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/your-username/celestlsh-cli.git
cd celestlsh-cli

# Build the binary
go build -o celestlsh-cli

# Move to a directory in your PATH (optional)
sudo mv celestlsh-cli /usr/local/bin/
```

## Usage

### Calculate TLSH hash of a file

```bash
celestlsh-cli -h <file_path>
celestlsh-cli --hash <file_path>
```

Example:
```bash
celestlsh-cli -h /path/to/file.exe
```

### Calculate distance between two TLSH hashes

```bash
celestlsh-cli -d <hash1> <hash2>
celestlsh-cli --distance <hash1> <hash2>
```

Example:
```bash
celestlsh-cli -d T1B1B383263802413407F383A9FD9AF41CEB1590A799AB5518F8ECD1C01F76905EAB9F9F T1E6B383263802413407F383A9FD9AF41CEB1590A799AB5518F8ECD1C01F76905EAB9F9F
```

### Download the CSV database of TLSH hashes

```bash
celestlsh-cli -dl [--db <output_path>]
celestlsh-cli --download [--db <output_path>]
```

Example:
```bash
celestlsh-cli -dl --db ~/tlsh_database.csv
```

### Check a TLSH hash against the database

```bash
celestlsh-cli -c <hash> [--db <database_path>]
celestlsh-cli --check <hash> [--db <database_path>]
```

Example:
```bash
celestlsh-cli -c T1B1B383263802413407F383A9FD9AF41CEB1590A799AB5518F8ECD1C01F76905EAB9F9F
```

## Output Options

### Quiet Mode

The `--quiet` flag outputs only the essential information:
- For hash calculation: only the hash
- For distance calculation: only the distance value
- For database checks: only the SHA256 hash of the closest match

```bash
celestlsh-cli -h /path/to/file.exe --quiet
```

### CSV Output

The `--csv` flag (only applies to database checks) outputs the results in CSV format:
```bash
celestlsh-cli -c <hash> --csv
```

Output format: `RepoName,FileName,Version,SHA256Hash,Distance`

## Database

The tool uses a CSV database of TLSH hashes from known attack tools. The database structure is:

```
Repo Name,File Name,Release Version,TLSH Hash,SHA256 Hash,Imphash,Date Added,Intel
```

The default database is hosted on GitHub at the Magonia-Research repository.

## How It Works

1. **Calculating TLSH Hashes**: 
   - The tool reads the entire file into memory
   - It uses the `glaslos/tlsh` Go library to calculate the TLSH hash
   - The minimum file size required is 256 bytes

2. **Calculating Distance**:
   - Two TLSH hashes are parsed using the TLSH library
   - The `Diff()` method calculates their similarity distance
   - Lower values indicate higher similarity

3. **Database Checks**:
   - The tool compares the input hash against all hashes in the database
   - It calculates the distance score for each comparison
   - Results are sorted by distance (lowest/most similar first)
   - The best match is returned

## Example Use Cases

### Malware Analysis

```bash
# Calculate the TLSH hash of a suspicious file
celestlsh-cli -h suspicious_file.exe

# Check if it matches any known attack tools
celestlsh-cli -c <calculated_hash>
```

### Checking for Similar Variants

```bash
# Calculate distance between two potentially related files
celestlsh-cli -h file1.bin > hash1.txt
celestlsh-cli -h file2.bin > hash2.txt
celestlsh-cli -d $(cat hash1.txt) $(cat hash2.txt)
```

### Batch Processing

```bash
#!/bin/bash
# Process all executables in a directory
for file in /path/to/dir/*.exe; do
  echo "Processing $file..."
  hash=$(celestlsh-cli -h "$file" --quiet)
  echo "Hash: $hash"
  celestlsh-cli -c "$hash" --csv >> results.csv
done
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- This tool uses the [glaslos/tlsh](https://github.com/glaslos/tlsh) Go implementation of TLSH
- TLSH was originally developed by Trend Micro
- The database of TLSH hashes is maintained by Magonia Research