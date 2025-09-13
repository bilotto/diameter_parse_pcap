# Diameter Parse PCAP

A Python library for parsing and analyzing Diameter protocol messages from network packet captures (PCAP files). Built on top of the [diameter](https://github.com/mensonen/diameter) and [diameter_telecom](https://github.com/bilotto/diameter_telecom) libraries, it provides comprehensive tools for extracting, processing, and analyzing Diameter traffic in telecommunications networks.

## Overview

Diameter Parse PCAP is designed for telecom engineers, network analysts, and developers who need to:
- Parse Diameter messages from PCAP files
- Analyze 3GPP network traffic (Gx, Rx, Sy applications)
- Extract session information and subscriber data
- Process multiple PCAP files efficiently
- Generate reports and statistics from network captures

The library extends the base Diameter protocol capabilities with telecom-specific parsing, session management, and advanced PCAP processing features.

## Architecture

Diameter Parse PCAP builds upon a three-layer architecture:

```
📊 Analysis Layer (diameter_parse_pcap)
├─ PcapGroup        → Batch PCAP processing with filtering
├─ Pcap             → Individual PCAP file handling
├─ DiameterMessagePcap → Extended message with PCAP metadata
└─ CsvFile          → Export capabilities

🔧 Telecom Layer (diameter_telecom)
├─ SessionManager   → Centralized session orchestration
├─ DiameterMessage  → Enhanced message processing
├─ Subscriber       → Telecom entity management
└─ Session Classes  → Gx/Rx/Sy session handling

⚙️ Base Layer (diameter library)
└─ Core Diameter protocol implementation
```

## Features

### Core PCAP Processing
- **Multi-format Support**: Handles .pcap, .pcapng, and compressed formats
- **Flexible Filtering**: Wireshark-style filters for Diameter traffic
- **Port Configuration**: Support for TCP and SCTP transports
- **Batch Processing**: Efficient handling of multiple PCAP files
- **Error Resilience**: Graceful handling of corrupted or incomplete captures

### Advanced Analysis Capabilities
- **Session Reconstruction**: Automatic Diameter session identification and tracking
- **Subscriber Extraction**: MSISDN, IMSI, and other telecom identifiers
- **Cross-Application Binding**: Links Gx, Rx, and Sy sessions intelligently
- **Message Correlation**: Associates requests with responses across sessions
- **Timeline Analysis**: Chronological message ordering and analysis

### Telecom-Specific Features
- **3GPP Application Support**: Gx (Policy), Rx (Media), Sy (Charging)
- **AVP Parsing**: Specialized parsing for telecom-specific AVPs
- **Session Management**: Complete session lifecycle tracking
- **Subscriber Management**: Carrier and APN information extraction
- **Usage Monitoring**: Service unit tracking and analysis

### Export and Reporting
- **CSV Export**: Structured data export for analysis tools
- **JSON Serialization**: Complete session manager data export
- **Statistics Generation**: Comprehensive traffic analysis reports
- **MCP Integration**: Cursor IDE integration for interactive analysis

## Installation

Since this package is not yet available on PyPI, you'll need to install it from source along with its dependencies:

```bash
# Clone the repository
git clone <repository-url>
cd diameter_libs

# Install base diameter library
cd diameter
pip install -e .

# Install diameter_telecom library
cd ../diameter_telecom
pip install -r requirements.txt
pip install -e .

# Install diameter_parse_pcap
cd ../diameter_parse_pcap
pip install -e .
```

### Dependencies

- **diameter**: Base Diameter protocol library
- **diameter_telecom**: Telecom-specific Diameter extensions
- **pyshark**: Python wrapper for Wireshark's tshark
- **tshark**: Wireshark command-line tools (system dependency)

### System Requirements

- Python 3.10+
- Wireshark/tshark installed and accessible in PATH
- Linux/macOS/Windows with WSL2 support

## Quick Start

### Basic PCAP Analysis

```python
from diameter_parse_pcap import Pcap, PcapGroup
from diameter_telecom.diameter.session_manager import SessionManager

# Single PCAP file analysis
pcap = Pcap(
    filepath="/path/to/capture.pcap",
    ports=[3868, 3869],  # Diameter ports
    filter="diameter && diameter.cmd.code != 257 && diameter.cmd.code != 280"
)

# Extract Diameter messages
messages = pcap.get_diameter_messages_from_pcap()
print(f"Found {len(messages)} Diameter messages")

# Process with session manager
session_manager = SessionManager()
for message in messages:
    session_manager.process_diameter_message(message)

# Access processed data
print(f"Sessions: {len(session_manager.sessions)}")
print(f"Subscribers: {len(session_manager.subscribers)}")
```

### Batch PCAP Processing

```python
from diameter_parse_pcap import PcapGroup

# Process multiple PCAPs with pattern matching
pcap_group = PcapGroup(
    directory="/data/pcaps",
    name_pattern=r".*claro.*\.pcap.*",  # Regex pattern
    ports=[31012, 31117],
    filter="diameter"
)

# Load and process all matching PCAPs
pcap_group.load_pcaps()
pcap_group.process_all_pcaps()

# Get summary statistics
summary = pcap_group.get_summary()
print(f"Processed {summary['total_pcaps']} PCAPs")
print(f"Total messages: {summary['total_messages']}")
```

### Advanced Session Analysis

```python
from diameter_parse_pcap import PcapGroup
from diameter_telecom.diameter.session_manager import SessionManager

# Create session manager for advanced analysis
session_manager = SessionManager()

# Process PCAPs with session management
pcap_group = PcapGroup(
    directory="/data",
    name_pattern=r".*\.pcap.*",
    ports=[3868, 3869]
)
pcap_group.set_session_manager(session_manager)
pcap_group.process_all_pcaps()

# Analyze session data
sessions = session_manager.sessions
for app_id, app_sessions in sessions.sessions.items():
    print(f"Application {app_id}: {len(app_sessions)} sessions")
    
    for session_id, session in app_sessions.items():
        print(f"  Session {session_id}: {len(session.messages)} messages")
        if hasattr(session, 'subscriber'):
            print(f"    Subscriber: {session.subscriber.msisdn}")

# Export to JSON for further analysis
json_data = session_manager.to_json()
```

## Key Components

### Pcap Class

The core class for handling individual PCAP files:

```python
pcap = Pcap(
    filepath="/path/to/file.pcap",
    ports=[3868, 3869],           # Diameter ports
    sctp=False,                   # Use TCP (default) or SCTP
    filter="diameter",            # Wireshark filter
    start_timestamp=None,         # Auto-detected
    end_timestamp=None            # Auto-detected
)

# Properties
print(f"Filename: {pcap.filename}")
print(f"Duration: {pcap.end_date - pcap.start_date}")
print(f"Messages: {pcap.n_diameter_messages}")

# Extract messages
messages = pcap.get_diameter_messages_from_pcap()
```

### PcapGroup Class

Manages multiple PCAP files with advanced filtering and processing:

```python
pcap_group = PcapGroup(
    directory="/data/pcaps",
    name_pattern=r".*volte.*\.pcap.*",  # Regex for filename matching
    ports=[3868, 3869],
    filter="diameter && diameter.cmd.code == 272",  # Only CCR messages
    sctp=False,
    recursive=True  # Search subdirectories
)

# Time-based filtering
from datetime import datetime, timedelta
recent_pcaps = pcap_group.get_pcaps_by_time_range(
    datetime.now() - timedelta(hours=1),
    datetime.now()
)

# Pattern-based filtering
volte_pcaps = pcap_group.get_pcaps_by_name_pattern(r".*volte.*")
```

### DiameterMessagePcap Class

Extended Diameter message with PCAP-specific metadata:

```python
# Access PCAP metadata
message.pkt_number          # Packet number in PCAP
message.pcap_filepath       # Source PCAP file
message.timestamp          # Message timestamp

# Access telecom data (if processed with SessionManager)
message.subscriber         # Subscriber object
message.framed_ip_address  # IP address
message.sgsn_mcc_mnc      # Network identifier
message.granted_service_unit  # Usage data
```

### CsvFile Class

Export capabilities for analysis tools:

```python
from diameter_parse_pcap import CsvFile

csv_file = CsvFile("analysis_results.csv")
csv_file.write_row({
    'timestamp': message.timestamp,
    'session_id': message.session_id,
    'msisdn': message.subscriber.msisdn if message.subscriber else '',
    'app_id': message.app_id,
    'result_code': message.result_code
})
csv_file.close()
```

## Advanced Usage

### Custom Message Processing

```python
def custom_message_handler(diameter_message):
    """Custom handler for processing Diameter messages."""
    if diameter_message.app_id == 16777238:  # Gx application
        print(f"Gx message: {diameter_message.name}")
        if hasattr(diameter_message, 'subscriber'):
            print(f"  Subscriber: {diameter_message.subscriber.msisdn}")
    
    # Add custom processing logic here
    return diameter_message

# Use custom handler
pcap_group.process_all_pcaps(custom_message_handler)
```

### Performance Optimization

```python
# For large PCAP files, use filtering to reduce processing time
pcap = Pcap(
    filepath="large_capture.pcap",
    ports=[3868],
    filter="diameter && diameter.cmd.code == 272 && diameter.cc_request_type == 1"  # Only CCR-I
)

# Process in chunks for memory efficiency
for pcap in pcap_group:
    if pcap.n_diameter_messages > 10000:
        print(f"Skipping large file: {pcap.filename}")
        continue
    pcap_group.process_single_pcap(pcap)
```

### Integration with MCP (Model Context Protocol)

The library includes MCP integration for use with Cursor IDE:

```bash
# Start MCP server
cd pcap-analyzer-mcp
pip install -r requirements.txt
python app.py  # Runs on http://localhost:8787
```

Available MCP tools:
- `pcap_list`: List PCAP files matching patterns
- `pcap_analyze_group`: Complete PCAP analysis with SessionManager JSON output

## Examples

The library includes comprehensive examples in the `examples/` directory:

### Basic Examples

1. **`pcap_group_example.py`** - Complete PcapGroup usage demonstration
   - Single and batch PCAP processing
   - Pattern-based filtering
   - Time-based analysis
   - Custom message handlers
   - Performance comparisons

### Real-World Scenarios

2. **VoLTE Analysis** - Voice over LTE traffic analysis
3. **Data Session Tracking** - Gx application session monitoring
4. **Charging Analysis** - Sy application spending limit tracking
5. **Multi-Application Correlation** - Cross-application session binding

## API Reference

### Core Classes

#### Pcap
- `__init__(filepath, ports, sctp, filter, ...)`
- `get_diameter_messages_from_pcap()` → List[DiameterMessagePcap]
- `get_timestamps()` → None
- `to_dict()` → dict

#### PcapGroup
- `__init__(directory, name_pattern, ports, filter, ...)`
- `load_pcaps()` → None
- `process_all_pcaps(message_handler=None)` → List
- `get_pcaps_by_time_range(start, end)` → List[Pcap]
- `get_pcaps_by_name_pattern(pattern)` → List[Pcap]
- `get_summary()` → dict

#### DiameterMessagePcap
- Inherits from `diameter_telecom.DiameterMessage`
- Additional attributes: `pkt_number`, `pcap_filepath`, `timestamp`
- Telecom attributes: `subscriber`, `framed_ip_address`, `sgsn_mcc_mnc`

#### CsvFile
- `__init__(filename, csv_columns, replace_existing)`
- `write_row(row_dict)` → None
- `close()` → None

### Utility Functions

- `read_pcap_json(file_path)` → List[Dict]
- `create_from_dict(pcap_dict)` → Pcap
- `get_diameter_messages_from_pcap(pcap)` → List[DiameterMessagePcap]
- `get_diameter_messages_from_pkt(pkt)` → List[DiameterMessagePcap]

## Performance Considerations

### Memory Management
- Large PCAP files are processed incrementally
- Session data is optimized for telecom-scale throughput
- Automatic cleanup of terminated sessions

### Processing Speed
- Multi-threaded PCAP processing support
- Efficient regex pattern matching
- Optimized Diameter message parsing

### Scalability
- Handles thousands of PCAP files
- Supports millions of Diameter messages
- Memory-efficient session storage

## Troubleshooting

### Common Issues

1. **TShark not found**
   ```bash
   # Install Wireshark
   sudo apt-get install tshark  # Ubuntu/Debian
   brew install wireshark       # macOS
   ```

2. **Permission denied for PCAP files**
   ```bash
   # Run with appropriate permissions
   sudo python your_script.py
   ```

3. **Memory issues with large PCAPs**
   ```python
   # Use filtering to reduce data
   pcap = Pcap(filepath="large.pcap", filter="diameter && diameter.cmd.code == 272")
   ```

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Process with verbose output
pcap_group.process_all_pcaps()
```

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd diameter_libs/diameter_parse_pcap

# Install in development mode
pip install -e .

# Run tests
python -m pytest tests/
```

## License

This project is licensed under the same terms as the base diameter library.

## Acknowledgments

- Built on the excellent [diameter](https://github.com/mensonen/diameter) library
- Extends [diameter_telecom](https://github.com/bilotto/diameter_telecom) for telecom-specific features
- Uses [pyshark](https://github.com/KimiNewt/pyshark) for PCAP processing
- Integrates with [Wireshark](https://www.wireshark.org/) for packet analysis

## Related Projects

- [diameter](https://github.com/mensonen/diameter) - Base Diameter protocol library
- [diameter_telecom](https://github.com/bilotto/diameter_telecom) - Telecom-specific Diameter extensions
- [pcap-analyzer-mcp](https://github.com/bilotto/diameter_libs/tree/main/pcap-analyzer-mcp) - MCP integration for Cursor IDE
