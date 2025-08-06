#!/usr/bin/env python3
"""
Mist NAC Tag Manager
Interactive script to manage NAC tags via Mist API

Copyright (C) 2025 Chris Smolen 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import requests
import json
import sys
import os
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import List, Dict, Optional


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_config(config: dict, password: str) -> dict:
    """Encrypt sensitive configuration data"""
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive key from password
    key = derive_key_from_password(password, salt)
    fernet = Fernet(key)
    
    # Encrypt sensitive data
    encrypted_token = fernet.encrypt(config['api_token'].encode()).decode()
    encrypted_org_id = fernet.encrypt(config['org_id'].encode()).decode()
    
    return {
        'api_endpoint': config['api_endpoint'],  # Not sensitive, keep plain
        'encrypted_api_token': encrypted_token,
        'encrypted_org_id': encrypted_org_id,
        'salt': base64.b64encode(salt).decode(),
        'encrypted': True
    }


def decrypt_config(encrypted_config: dict, password: str) -> dict:
    """Decrypt configuration data"""
    try:
        # Get salt and derive key
        salt = base64.b64decode(encrypted_config['salt'])
        key = derive_key_from_password(password, salt)
        fernet = Fernet(key)
        
        # Decrypt sensitive data
        api_token = fernet.decrypt(encrypted_config['encrypted_api_token'].encode()).decode()
        org_id = fernet.decrypt(encrypted_config['encrypted_org_id'].encode()).decode()
        
        return {
            'api_endpoint': encrypted_config['api_endpoint'],
            'api_token': api_token,
            'org_id': org_id
        }
    except Exception as e:
        raise Exception(f"Failed to decrypt configuration. Wrong password? {e}")


def load_saved_config():
    """Load saved configuration if it exists"""
    config_file = os.path.expanduser("~/.mist_nac_config.json")
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Check if config is encrypted
            if config.get('encrypted', False):
                print("📁 Found encrypted saved configuration")
                
                # Allow multiple password attempts
                max_attempts = 3
                for attempt in range(max_attempts):
                    password = getpass.getpass("Enter password to decrypt configuration: ")
                    
                    try:
                        decrypted = decrypt_config(config, password)
                        print("✅ Configuration decrypted successfully!")
                        return decrypted['api_endpoint'], decrypted['api_token'], decrypted['org_id']
                    except Exception as e:
                        remaining = max_attempts - attempt - 1
                        if remaining > 0:
                            print(f"❌ Incorrect password. {remaining} attempt(s) remaining.")
                        else:
                            print("❌ Maximum password attempts exceeded.")
                            print("💡 Choose 'Clear saved configuration' from the main menu if you've forgotten your password.")
                
                # All attempts failed
                print("🔄 Continuing with manual setup...")
                return None, None, None
            else:
                # Legacy unencrypted config
                print("📁 Found unencrypted saved configuration")
                return config.get('api_endpoint'), config.get('api_token'), config.get('org_id')
                
        except Exception as e:
            print(f"Error loading saved config: {e}")
    
    return None, None, None


def save_config(api_endpoint: str, api_token: str, org_id: str):
    """Save configuration to file with encryption"""
    config_file = os.path.expanduser("~/.mist_nac_config.json")
    
    config = {
        'api_endpoint': api_endpoint,
        'api_token': api_token,
        'org_id': org_id
    }
    
    # Ask for encryption password
    print("\n🔐 To encrypt your credentials, please set a password:")
    while True:
        password = getpass.getpass("Enter encryption password: ")
        password_confirm = getpass.getpass("Confirm password: ")
        
        if password == password_confirm:
            if len(password) < 6:
                print("Password must be at least 6 characters long.")
                continue
            break
        else:
            print("Passwords don't match. Please try again.")
    
    try:
        # Encrypt the config
        encrypted_config = encrypt_config(config, password)
        
        # Save encrypted config
        with open(config_file, 'w') as f:
            json.dump(encrypted_config, f, indent=2)
        
        # Set restrictive file permissions (user read/write only)
        os.chmod(config_file, 0o600)
        
        print(f"✅ Encrypted configuration saved to {config_file}")
        print("🔒 Your API token and org ID are now encrypted!")
        return True
    except Exception as e:
        print(f"❌ Error saving encrypted config: {e}")
        return False


def setup_configuration():
    """Get configuration from user"""
    print("MIST NAC TAG MANAGER - SETUP")
    print("="*40)
    
    # Check for saved config first
    saved_endpoint, saved_token, saved_org_id = load_saved_config()
    
    if saved_endpoint and saved_token and saved_org_id:
        print(f"\n📁 Found saved configuration:")
        print(f"   API Endpoint: {saved_endpoint}")
        print(f"   Organization ID: {saved_org_id}")
        print(f"   API Token: {'*' * (len(saved_token) - 4) + saved_token[-4:]}")
        
        use_saved = input("\nUse saved configuration? (y/n): ").strip().lower()
        if use_saved in ['y', 'yes']:
            return saved_endpoint, saved_token, saved_org_id
    
    # Get API endpoint via menu
    print("\nSelect your Mist API region:")
    print("1. Global 01 (https://api.mist.com)")
    print("2. Global 02 (https://api.gc1.mist.com)")
    print("3. Global 03 (https://api.ac2.mist.com)")
    
    endpoints = {
        '1': 'https://api.mist.com',
        '2': 'https://api.gc1.mist.com', 
        '3': 'https://api.ac2.mist.com'
    }
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        if choice in endpoints:
            api_endpoint = endpoints[choice]
            print(f"Selected: {api_endpoint}")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")
    
    # Get organization ID
    print("\nYou can find your org_id in the Mist portal URL when logged in")
    org_id = input("Enter your organization ID: ").strip()
    
    # Get API token
    print("\nCreate an API token in: Organization > Admin > API Tokens")
    api_token = input("Enter your API token: ").strip()
    
    # Ask if user wants to save config
    save_choice = input("\n💾 Save this configuration for future use? (y/n): ").strip().lower()
    if save_choice in ['y', 'yes']:
        save_config(api_endpoint, api_token, org_id)
    
    return api_endpoint, api_token, org_id


class MistNacManager:
    def __init__(self, api_endpoint: str, api_token: str, org_id: str):
        self.api_endpoint = api_endpoint.rstrip('/')
        self.api_token = api_token
        self.org_id = org_id
        self.debug_mode = False  # Add debug mode toggle
        self.headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Token {api_token}'
        }
        self.base_url = f"{self.api_endpoint}/api/v1/orgs/{self.org_id}/nactags"
    
    def debug_print(self, message: str):
        """Print debug message only if debug mode is enabled"""
        if self.debug_mode:
            print(message)
    
    def get_all_nac_tags(self) -> List[Dict]:
        """Retrieve all NAC tags for the organization"""
        try:
            response = requests.get(self.base_url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching NAC tags: {e}")
            return []
    
    def get_nac_tag(self, nactag_id: str) -> Optional[Dict]:
        """Get a specific NAC tag by ID"""
        try:
            url = f"{self.base_url}/{nactag_id}"
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching NAC tag {nactag_id}: {e}")
            return None
    
    def update_nac_tag(self, nactag_id: str, tag_data: Dict) -> bool:
        """Update a NAC tag"""
        try:
            url = f"{self.base_url}/{nactag_id}"
            self.debug_print(f"DEBUG: Making PUT request to: {url}")
            self.debug_print(f"DEBUG: Request payload: {json.dumps(tag_data, indent=2)}")
            
            response = requests.put(url, headers=self.headers, json=tag_data)
            
            self.debug_print(f"DEBUG: Response status: {response.status_code}")
            self.debug_print(f"DEBUG: Response content: {response.text}")
            
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Error updating NAC tag: {e}")
            return False
    
    def normalize_mac_address(self, mac: str) -> str:
        """Normalize MAC address to lowercase with no separators"""
        # Remove all common separators and convert to lowercase
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '').lower()
        return mac_clean
    
    def validate_mac_address(self, mac: str) -> bool:
        """Validate MAC address format and normalize it"""
        # Normalize the MAC address
        mac_clean = self.normalize_mac_address(mac)
        
        # Should be 12 hex characters
        if len(mac_clean) != 12:
            return False
        
        try:
            int(mac_clean, 16)  # Check if it's valid hex
            return True
        except ValueError:
            return False
    
    def add_mac_address(self, nactag_id: str, tag: Dict):
        """Add a MAC address to the NAC tag"""
        self.debug_print("DEBUG: *** RUNNING NEW VERSION OF add_mac_address ***")
        current_values = tag.get('values') or []
        self.debug_print(f"DEBUG: Current values from tag: {current_values}")
        
        print("\nSupported MAC address formats:")
        print("  • aa:bb:cc:dd:ee:ff (colon separated)")
        print("  • aa-bb-cc-dd-ee-ff (dash separated)")
        print("  • 001a.2b3c.4d5e (Cisco dot notation)")
        print("  • aabbccddeeff (no separators)")
        print("  → All formats will be normalized to lowercase without separators")
        
        while True:
            new_mac = input("\nEnter MAC address to add (or 'cancel' to abort): ").strip()
            
            if new_mac.lower() == 'cancel':
                return
            
            # Validate MAC address format
            if self.validate_mac_address(new_mac):
                # Normalize the new MAC address
                normalized_new_mac = self.normalize_mac_address(new_mac)
                self.debug_print(f"DEBUG: Input '{new_mac}' normalized to '{normalized_new_mac}'")
                
                # Normalize ALL existing MACs
                normalized_existing_macs = []
                for existing_mac in current_values:
                    normalized_existing = self.normalize_mac_address(existing_mac)
                    normalized_existing_macs.append(normalized_existing)
                    self.debug_print(f"DEBUG: Existing '{existing_mac}' normalized to '{normalized_existing}'")
                
                # Check for duplicates using normalized versions
                if normalized_new_mac in normalized_existing_macs:
                    print(f"MAC address {normalized_new_mac} already exists in the tag.")
                    continue
                
                # Create the final normalized values list
                final_values = normalized_existing_macs + [normalized_new_mac]
                self.debug_print(f"DEBUG: Final values list to send: {final_values}")
                
                # Build a completely fresh payload - don't copy anything from original
                payload = {
                    'name': tag.get('name'),
                    'type': tag.get('type'),
                    'match': tag.get('match'),
                    'values': final_values
                }
                
                # Only add description if it exists and isn't empty
                desc = tag.get('description')
                if desc and desc.strip():
                    payload['description'] = desc
                
                self.debug_print(f"DEBUG: Clean payload to send: {json.dumps(payload, indent=2)}")
                
                if self.update_nac_tag(nactag_id, payload):
                    print("✅ MAC address added successfully!")
                    break
                else:
                    print("❌ Failed to update NAC tag")
                    break
            else:
                print("❌ Invalid MAC address format.")
                print("Please use one of these formats:")
                print("  • aa:bb:cc:dd:ee:ff")
                print("  • aa-bb-cc-dd-ee-ff") 
                print("  • 001a.2b3c.4d5e")
                print("  • aabbccddeeff")
    
    def remove_mac_address(self, nactag_id: str, tag: Dict):
        """Remove a MAC address from the NAC tag"""
        current_values = tag.get('values') or []
        
        if not current_values:
            print("No MAC addresses to remove.")
            return
        
        print("\nCurrent MAC addresses:")
        for i, mac in enumerate(current_values, 1):
            print(f"  {i:2d}. {mac}")
        
        while True:
            choice = input(f"\nSelect MAC to remove (1-{len(current_values)}) or 'cancel': ").strip()
            
            if choice.lower() == 'cancel':
                return
            
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(current_values):
                    mac_to_remove = current_values[choice_num - 1]
                    
                    # Remove from values and normalize remaining ones
                    remaining_values = [mac for mac in current_values if mac != mac_to_remove]
                    normalized_remaining = [self.normalize_mac_address(mac) for mac in remaining_values]
                    
                    # Create updated tag data
                    updated_tag = {
                        'name': tag.get('name'),
                        'type': tag.get('type'),
                        'match': tag.get('match'),
                        'values': normalized_remaining
                    }
                    
                    if tag.get('description'):
                        updated_tag['description'] = tag.get('description')
                    
                    print(f"\nRemoving MAC address: {mac_to_remove}")
                    if self.update_nac_tag(nactag_id, updated_tag):
                        print("✅ MAC address removed successfully!")
                        break
                    else:
                        print("❌ Failed to update NAC tag")
                        break
                else:
                    print(f"Please enter a number between 1 and {len(current_values)}")
            except ValueError:
                print("Please enter a valid number or 'cancel'")
    
    def display_tags_menu(self) -> Optional[str]:
        """Display all NAC tags and let user select one"""
        tags = self.get_all_nac_tags()
        
        if not tags:
            print("No NAC tags found or error retrieving tags.")
            return None
        
        print("\n" + "="*60)
        print("AVAILABLE NAC TAGS")
        print("="*60)
        
        for i, tag in enumerate(tags, 1):
            name = tag.get('name') or 'Unnamed'
            tag_type = tag.get('type') or 'Unknown'
            match_type = tag.get('match') or 'Unknown'
            values_count = len(tag.get('values') or [])
            print(f"{i:2d}. {name:<20} | Type: {tag_type:<8} | Match: {match_type:<12} | Values: {values_count}")
        
        print(f"{len(tags)+1:2d}. Back to main menu")
        
        while True:
            try:
                choice = input(f"\nSelect a tag (1-{len(tags)+1}): ").strip()
                choice_num = int(choice)
                
                if choice_num == len(tags) + 1:
                    return None
                elif 1 <= choice_num <= len(tags):
                    return tags[choice_num - 1].get('id')
                else:
                    print(f"Please enter a number between 1 and {len(tags)+1}")
            except ValueError:
                print("Please enter a valid number")
    
    def display_tag_details(self, nactag_id: str) -> Optional[Dict]:
        """Display detailed information about a specific NAC tag"""
        tag = self.get_nac_tag(nactag_id)
        
        if not tag:
            return None
        
        print("\n" + "="*60)
        print("NAC TAG DETAILS")
        print("="*60)
        print(f"Name: {tag.get('name') or 'Unnamed'}")
        print(f"Type: {tag.get('type') or 'Unknown'}")
        print(f"Match Criteria: {tag.get('match') or 'Unknown'}")
        print(f"Description: {tag.get('description') or 'No description'}")
        
        values = tag.get('values') or []
        print(f"\nCurrent Values ({len(values)} items):")
        if values:
            for i, value in enumerate(values, 1):
                print(f"  {i:2d}. {value}")
        else:
            print("  No values configured")
        
        return tag
    
    def tag_management_menu(self, nactag_id: str):
        """Management menu for a specific NAC tag"""
        while True:
            tag = self.display_tag_details(nactag_id)
            if not tag:
                break
            
            print("\n" + "-"*60)
            print("TAG MANAGEMENT OPTIONS")
            print("-"*60)
            print("1. Add MAC address")
            print("2. Remove MAC address")
            print("3. Refresh tag details")
            print("4. Back to tag selection")
            
            choice = input("\nSelect an option (1-4): ").strip()
            
            if choice == '1':
                self.add_mac_address(nactag_id, tag)
            elif choice == '2':
                self.remove_mac_address(nactag_id, tag)
            elif choice == '3':
                continue  # Will refresh on next loop
            elif choice == '4':
                break
            else:
                print("Invalid choice. Please select 1-4.")
    
    def main_menu(self):
        """Main application menu"""
        print("\n" + "="*60)
        print("MIST NAC TAG MANAGER")
        print("="*60)
        print(f"Organization ID: {self.org_id}")
        print(f"API Endpoint: {self.api_endpoint}")
        print(f"Debug Mode: {'ON' if self.debug_mode else 'OFF'}")
        print("="*60)
        
        while True:
            print("\nMAIN MENU")
            print("-" * 20)
            print("1. View all NAC tags")
            print("2. Manage a NAC tag")
            print("3. Toggle debug mode")
            print("4. Clear saved configuration")
            print("5. Exit")
            
            choice = input("\nSelect an option (1-5): ").strip()
            
            if choice == '1':
                self.view_all_tags()
            elif choice == '2':
                nactag_id = self.display_tags_menu()
                if nactag_id:
                    self.tag_management_menu(nactag_id)
            elif choice == '3':
                self.toggle_debug_mode()
            elif choice == '4':
                self.clear_saved_config()
            elif choice == '5':
                print("Goodbye!")
                sys.exit(0)
            else:
                print("Invalid choice. Please select 1-5.")
    
    def toggle_debug_mode(self):
        """Toggle debug mode on/off"""
        self.debug_mode = not self.debug_mode
        status = "ON" if self.debug_mode else "OFF"
        print(f"🔧 Debug mode turned {status}")
        if self.debug_mode:
            print("   Debug information will be shown during API operations")
        else:
            print("   Debug information will be hidden for cleaner output")
    
    def clear_saved_config(self):
        """Clear saved configuration file"""
        config_file = os.path.expanduser("~/.mist_nac_config.json")
        
        if os.path.exists(config_file):
            confirm = input("Are you sure you want to clear saved configuration? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                try:
                    os.remove(config_file)
                    print("✅ Saved configuration cleared successfully!")
                    print("You'll need to re-enter your credentials on next run.")
                except Exception as e:
                    print(f"❌ Error clearing config: {e}")
        else:
            print("No saved configuration found.")
    
    def view_all_tags(self):
        """Display all NAC tags in simple format"""
        tags = self.get_all_nac_tags()
        
        if not tags:
            print("No NAC tags found.")
            return
        
        print("\n" + "="*40)
        print("ALL NAC TAGS")
        print("="*40)
        
        for i, tag in enumerate(tags, 1):
            name = tag.get('name') or 'Unnamed'
            values_count = len(tag.get('values') or [])
            print(f"{i:2d}. {name} ({values_count} values)")
        
        input("\nPress Enter to continue...")


def check_dependencies():
    """Check if required dependencies are available"""
    missing_packages = []
    
    try:
        import requests
    except ImportError:
        missing_packages.append('requests')
    
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        missing_packages.append('cryptography')
    
    return missing_packages


def main():
    """Main application entry point"""
    try:
        print("Mist NAC Tag Manager")
        print("Copyright (C) 2025 [Your Name]")
        print("Licensed under AGPL-3.0 - https://www.gnu.org/licenses/agpl-3.0.html")
        print("-" * 60)
        
        # Check for missing dependencies (only if not running as executable)
        if not getattr(sys, 'frozen', False):
            missing = check_dependencies()
            if missing:
                print(f"\n❌ Missing required packages: {', '.join(missing)}")
                print("Install with: pip install cryptography requests")
                sys.exit(1)
        
        # Get configuration
        api_endpoint, api_token, org_id = setup_configuration()
        
        # Create manager instance
        manager = MistNacManager(api_endpoint, api_token, org_id)
        
        # Test connection
        print("\nTesting connection...")
        tags = manager.get_all_nac_tags()
        if tags is None:
            print("❌ Failed to connect to Mist API. Please check your credentials.")
            sys.exit(1)
        
        print(f"✅ Connected successfully! Found {len(tags)} NAC tag(s).")
        
        # Start main menu
        manager.main_menu()
        
    except ImportError as e:
        # Handle import errors gracefully
        if not getattr(sys, 'frozen', False):
            print("❌ Import error - missing required packages:")
            print("   pip install cryptography requests")
        else:
            print(f"❌ Import error in packaged application: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
