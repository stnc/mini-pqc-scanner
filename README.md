# Mini PQC Scanner

A streamlined, CLI-only version of the Post-Quantum Cryptography Scanner. This mini version focuses exclusively on core scanning functionality without web interfaces, Docker testing, or server components.

## Overview

Mini PQC Scanner is a command-line tool that audits systems for post-quantum cryptography readiness. It performs comprehensive scans of various system components including:

- **Environment** - System environment and security settings
- **Firmware** - Firmware security configurations  
- **Kernel** - Linux kernel PQC support
- **Libraries** - Cryptographic library analysis
- **Certificate Authority** - CA configuration assessment
- **Runtime** - Runtime environment PQC readiness
- **Network Services** - OpenSSH, OpenVPN, IPsec, WireGuard
- **Web Services** - Nginx, Apache configurations
- **Mail Services** - Postfix configuration
- **Certificates** - Certificate parsing and analysis
- **PGP** - PGP/GPG configuration assessment
- **TLS** - TLS handshake analysis
- **Network Traffic** - tcpdump-based traffic analysis

## Features

- **CLI-only Interface** - Pure command-line operation with optional TUI
- **Comprehensive Scanning** - Multiple security modules
- **JSON Output** - Machine-readable output format
- **Interactive Mode** - Built-in terminal UI for interactive use
- **Batch Mode** - Single command execution for automation

## Installation

### Build from Source

```bash
# Clone or extract the mini-pqc repository
cd mini-pqc

# Install dependencies
make deps

# Build the binary
make build

# The binary will be available at ./bin/mini-pqc-scanner
```

### Cross-Platform Builds

```bash
# Build for Linux
make build-linux

# Build for Windows  
make build-windows

# Build for macOS
make build-mac

# Build for all platforms
make build-all-platforms
```

## Usage

### Interactive Mode

Run without arguments to start the interactive TUI:

```bash
./bin/mini-pqc-scanner
```

This launches a terminal UI with:
- **Left Panel**: CLI input/output
- **Right Panel**: Recommendations and results
- **Tab Navigation**: Switch between panels

### Command Line Mode

Execute specific commands directly:

```bash
# Show version
./bin/mini-pqc-scanner version

# Show help
./bin/mini-pqc-scanner help

# Run environment scan
./bin/mini-pqc-scanner env

# Run comprehensive scan
./bin/mini-pqc-scanner all

# Run with JSON output
./bin/mini-pqc-scanner env -json
```

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `version` | Display version information |
| `config` | Configure scanner settings |
| `env` | Check environment security |
| `firmware` | Check firmware security |
| `kernel` | Check kernel PQC support |
| `lib` | Test cryptographic libraries |
| `ca` | Check Certificate Authority config |
| `runtime` | Check runtime environment |
| `openssh` | Check OpenSSH configuration |
| `openvpn` | Check OpenVPN configuration |
| `ipsec` | Check IPsec configuration |
| `wireguard` | Check WireGuard configuration |
| `nginx` | Check Nginx configuration |
| `apache` | Check Apache configuration |
| `postfix` | Check Postfix configuration |
| `pgp` | Check PGP configuration |
| `parsecrt` | Parse and analyze certificates |
| `tls` | Test TLS configuration |
| `tcpdump` | Analyze network traffic |
| `all` | Run all scan modules |

### Configuration

First-time setup requires configuration:

```bash
./bin/mini-pqc-scanner config
```

This will prompt for:
- Organization name
- License key (if applicable)
- Other scanner settings

### JSON Output
Machine-readable format for automation:

```bash
./bin/mini-pqc-scanner env -json
```

## Examples

### Basic System Scan
```bash
# Quick environment check
./bin/mini-pqc-scanner env

# Check kernel PQC support
./bin/mini-pqc-scanner kernel

# Analyze certificates
./bin/mini-pqc-scanner parsecrt -verbose
```

### Comprehensive Assessment
```bash
# Run all modules with JSON output
./bin/mini-pqc-scanner all -json > pqc-report.json

# Test specific service
./bin/mini-pqc-scanner openssh
./bin/mini-pqc-scanner nginx
```

### Network Analysis
```bash
# Test TLS configuration
./bin/mini-pqc-scanner tls example.com

# Analyze network traffic
./bin/mini-pqc-scanner tcpdump
```

## Development

### Project Structure

```
mini-pqc/
├── cmd/                    # Main application and CLI commands
│   ├── main.go            # Application entry point
│   └── commands/linux/    # Linux-specific command implementations
├── scan/                  # Core scanning functionality
├── rules/                 # PQC rules and definitions
├── config/                # Configuration sample
├── pkg/config/           # Configuration management
├── bin/                  # Built binaries
├── version/              # Version tracking
├── Makefile              # Build configuration
├── go.mod                # Go module definition
└── README.md             # This file
```

### Building

```bash
# Clean and rebuild
make clean && make build

# Run tests
make test

# Install to GOPATH/bin
make install
```

### Version Management

The build system automatically increments version numbers when source code changes are detected. Version information is stored in `version/scanner_version`.

## Differences from Full PQC Scanner

This mini version excludes:
- **Web Interface** - No webapp or webui components
- **Docker Testing** - No docker-test framework
- **A2A Server** - No agent-to-agent communication
- **CBOM Tools** - No Crypto Bill of Materials functionality
- **Deployment Scripts** - No remote installation scripts
- **Package Management** - Simplified pkg structure

## Requirements

- **Go 1.23.0+** for building from source
- **Linux Environment** for full functionality
- **Root/Sudo Access** for some system-level scans
- **Network Access** for external service testing

## License

See LICENSE file for licensing information.

## Support

For issues and questions related to the mini PQC scanner, please refer to the main PQC scanner documentation or contact your system administrator.
