# Mist NAC Tag Manager

A command-line tool for managing Network Access Control (NAC) tags in Juniper Mist via the REST API. Simplifies adding and removing MAC addresses from NAC tags with support for multiple MAC address formats and encrypted credential storage.

## Features

- **Interactive Menu System** - Easy-to-use text-based interface
- **Multiple MAC Address Formats** - Supports colon, dash, dot notation, and no separators
- **Automatic Normalization** - Converts all MAC addresses to consistent lowercase format
- **Encrypted Credential Storage** - Securely saves API credentials with password protection
- **Debug Mode Toggle** - Optional detailed logging for troubleshooting
- **Cross-Platform** - Works on Windows, macOS, and Linux
- **Self-Contained Executable** - No Python installation required for end users

## Supported MAC Address Formats

The tool accepts and automatically normalizes these formats:
- `aa:bb:cc:dd:ee:ff` (colon separated)
- `aa-bb-cc-dd-ee-ff` (dash separated)
- `001a.2b3c.4d5e` (Cisco dot notation)
- `aabbccddeeff` (no separators)

All formats are stored as lowercase without separators for consistency.

## Prerequisites

### For Python Script
- Python 3.7 or higher
- `cryptography` package
- `requests` package

### For Executable
- No prerequisites - completely self-contained

## Installation

### Option 1: Download Executable (Recommended)
1. Download the latest release from the [Releases](../../releases) page
2. Run the executable directly - no installation required

### Option 2: Run Python Script
```bash
# Clone or download the repository
git clone https://github.com/smolz/Mist-NAC-Tag-Manager.git
cd Mist-NAC-Tag-Manager

# Install dependencies
pip install cryptography requests

# Run the script
python mist_nac_manager.py
```

### Option 3: Build from Source
```bash
# Clone repository
git clone https://github.com/smolz/Mist-NAC-Tag-Manager.git
cd Mist-NAC-Tag-Manager

# Create virtual environment
python -m venv build_env
source build_env/bin/activate  # Linux/macOS
# or
build_env\Scripts\activate     # Windows

# Install dependencies
pip install pyinstaller cryptography requests

# Build executable
pyinstaller --onefile --console --icon=mist-nac-icon.ico --name "Mist NAC Manager" mist_nac_manager.py

# Find executable in dist/ folder
```

## Configuration

### Initial Setup
1. **API Token**: Create an API token in your Mist portal at Organization > Admin > API Tokens
2. **Organization ID**: Find your org ID in the Mist portal URL when logged in
3. **API Endpoint**: Choose your region:
   - Global 01: `https://api.mist.com`
   - Global 02: `https://api.gc1.mist.com`
   - Global 03: `https://api.ac2.mist.com`

### Credential Storage
- Credentials are encrypted and stored in `~/.mist_nac_config.json`
- Password-protected encryption using industry-standard methods
- Automatic detection and loading of saved configuration

## Usage

### Basic Workflow
1. **Start the application**
2. **Enter your credentials** (or use saved configuration)
3. **Choose from main menu:**
   - View all NAC tags
   - Manage a specific NAC tag
   - Toggle debug mode
   - Clear saved configuration

### Managing NAC Tags
1. Select "Manage a NAC tag" from main menu
2. Choose a tag from the list
3. View current MAC addresses
4. Add or remove MAC addresses as needed

### Example Session
```
Mist NAC Tag Manager
Copyright (C) 2025 Chris Smolen
Licensed under AGPL-3.0

MAIN MENU
1. View all NAC tags
2. Manage a NAC tag
3. Toggle debug mode
4. Clear saved configuration
5. Exit

Select an option (1-5): 2

AVAILABLE NAC TAGS
1. IoT Devices        | Type: match   | Match: client_mac  | Values: 15
2. Security Cameras   | Type: match   | Match: client_mac  | Values: 8
3. Printers          | Type: match   | Match: client_mac  | Values: 3

Select a tag (1-4): 1

Enter MAC address to add: 001A.2B3C.4D5E
✅ MAC address added successfully!
```

## Configuration File Location

The encrypted configuration file is stored at:
- **Windows**: `C:\Users\[username]\.mist_nac_config.json`
- **macOS**: `/Users/[username]/.mist_nac_config.json`
- **Linux**: `/home/[username]/.mist_nac_config.json`

## Security

- **API credentials encrypted** using Fernet (AES 128 in CBC mode)
- **Password-based key derivation** with PBKDF2 (100,000 iterations)
- **File permissions** restricted to user only (600)
- **No plaintext storage** of sensitive information

## Troubleshooting

### Common Issues

**"Failed to connect to Mist API"**
- Verify your API token is correct and active
- Check your organization ID
- Ensure you selected the correct API endpoint region
- Verify network connectivity

**"Missing required packages"**
- Only applies to Python script version
- Install missing packages: `pip install cryptography requests`

**"Incorrect password"**
- You have 3 attempts to enter the correct decryption password
- Use "Clear saved configuration" if password is forgotten
- Delete `~/.mist_nac_config.json` manually if needed

### Debug Mode
Enable debug mode (option 3) to see detailed API calls and responses for troubleshooting.

### Log Files
The application doesn't create log files by default. Enable debug mode for detailed output.

## API Rate Limits

- Mist API allows 5,000 calls per hour
- The application typically uses 2-3 API calls per operation
- Rate limit resets at the top of each hour

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/smolz/Mist-NAC-Tag-Manager.git
cd Mist-NAC-Tag-Manager
python -m venv dev_env
source dev_env/bin/activate
pip install -r requirements.txt
```

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

See the [LICENSE](LICENSE) file for the full license text.

### AGPL-3.0 Summary
- ✅ Commercial use allowed
- ✅ Modification allowed
- ✅ Distribution allowed
- ✅ Patent use granted
- ❗ Source code must be disclosed
- ❗ Network use triggers copyleft
- ❗ Same license required for derivatives

## Support

- **Issues**: Report bugs or request features via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions and community support
- **Documentation**: Additional documentation available in the `/docs` folder

## Changelog

### v1.0.0 (06 AUG 2025)
- Initial release
- Support for all major MAC address formats
- Encrypted credential storage
- Cross-platform executable builds
- Debug mode toggle

## Acknowledgments

- **Juniper Mist** for the comprehensive REST API
- **cryptography** library maintainers for secure encryption
- **PyInstaller** team for executable packaging
- **requests** library for HTTP client functionality

## Related Projects

- [Mist API Documentation](https://api.mist.com/api/v1/docs)
- [Juniper Mist Portal](https://manage.mist.com)

---

**Copyright (C) 2025 Chris Smolen**  
Licensed under AGPL-3.0 - https://www.gnu.org/licenses/agpl-3.0.html
