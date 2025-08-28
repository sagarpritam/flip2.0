#!/usr/bin/env python3
"""
PII Detection and Redaction System
Developed for ISCP PII Dataset Analysis
Author: Data Privacy Team
Version: 1.0
"""

import re
import json
import pandas as pd
import sys
import os
from typing import Dict, Any, Tuple, List

class PIIDetectorRedactor:
    """
    A comprehensive PII detection and redaction system that handles
    both standalone and combinatorial PII according to ISCP guidelines.
    """
    
    def __init__(self):
        # Configure detection parameters based on business requirements
        self.standalone_pii_fields = ['phone', 'aadhar', 'passport', 'upi_id']
        self.combinatorial_fields = ['name', 'email', 'address', 'device_id', 'ip_address']
        
    def normalize_json_value(self, value):
        """
        Handle different data formats including scientific notation
        that commonly appears in CSV exports from Excel/Google Sheets
        """
        if isinstance(value, (int, float)):
            # Handle large numbers that might be in scientific notation
            if value == int(value):
                return str(int(value))
            return str(value)
        return str(value) if value is not None else ''
    
    def is_valid_phone_number(self, phone_str):
        """
        Validate Indian mobile numbers (10 digits starting with 6,7,8,9)
        Also handles edge cases from data processing
        """
        digits_only = re.sub(r'\D', '', str(phone_str))
        return (len(digits_only) == 10 and 
                digits_only.isdigit() and 
                digits_only[0] in '6789')
    
    def is_valid_aadhar(self, aadhar_str):
        """
        Validate Aadhar format (12 digits)
        Handles various input formats including scientific notation
        """
        digits_only = re.sub(r'\D', '', str(aadhar_str))
        return len(digits_only) == 12 and digits_only.isdigit()
    
    def is_valid_passport(self, passport_str):
        """
        Validate Indian passport formats
        Common patterns: Letter followed by 7-8 digits
        """
        passport_clean = str(passport_str).upper().strip()
        # Indian passport patterns
        patterns = [
            r'^[A-Z]\d{7,8}$',          # Standard format: A1234567
            r'^[A-Z]{1,2}\d{6,7}$',     # Alternative: AB123456
        ]
        
        for pattern in patterns:
            if re.match(pattern, passport_clean):
                return True
        return False
    
    def is_valid_upi_id(self, upi_str):
        """
        Detect UPI payment IDs
        Format: username@provider (but not email addresses)
        """
        upi_clean = str(upi_str).strip()
        # Must have @ symbol but not be an email
        if '@' not in upi_clean:
            return False
            
        # Split and validate parts
        parts = upi_clean.split('@')
        if len(parts) != 2:
            return False
            
        username, provider = parts
        
        # UPI providers typically don't have dots in domain
        # This helps distinguish from emails
        if '.' in provider and len(provider.split('.')) > 1:
            return False
            
        # Common UPI providers
        upi_providers = ['paytm', 'ybl', 'okaxis', 'ibl', 'axl', 'hdfcbank', 
                        'icici', 'sbi', 'phonepe', 'gpay', 'amazonpay']
        
        return provider.lower() in upi_providers or len(provider) <= 10
    
    def is_valid_email(self, email_str):
        """
        Validate email addresses using comprehensive regex
        """
        email_clean = str(email_str).strip()
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email_clean))
    
    def is_full_name(self, name_str):
        """
        Detect full names (first + last name minimum)
        Handles Indian naming conventions
        """
        if not name_str or not isinstance(name_str, str):
            return False
            
        name_clean = str(name_str).strip()
        words = name_clean.split()
        
        # Need at least 2 words for full name
        if len(words) < 2:
            return False
            
        # Each word should be primarily alphabetic
        for word in words:
            if not re.match(r'^[A-Za-z][A-Za-z\.\-\']*$', word):
                return False
                
        # Filter out common non-name patterns
        non_name_patterns = ['test', 'user', 'admin', 'customer']
        if any(pattern in name_clean.lower() for pattern in non_name_patterns):
            return False
            
        return True
    
    def is_complete_address(self, address_str):
        """
        Detect complete addresses with street, city, and pincode
        """
        if not address_str or not isinstance(address_str, str):
            return False
            
        address_clean = str(address_str).strip()
        
        # Must have reasonable length for complete address
        if len(address_clean) < 20:
            return False
            
        # Should contain numbers (for street number and pincode)
        if not re.search(r'\d', address_clean):
            return False
            
        # Should have comma separators for multi-part address
        if ',' not in address_clean:
            return False
            
        parts = [part.strip() for part in address_clean.split(',')]
        
        # Should have at least 2 parts (street, city or city, pincode)
        if len(parts) < 2:
            return False
            
        # Check if last part looks like pincode (6 digits)
        last_part = parts[-1].strip()
        if re.match(r'^\d{6}$', last_part):
            return True
            
        # Alternative: check if any part contains 6-digit pincode
        for part in parts:
            if re.search(r'\b\d{6}\b', part):
                return True
                
        return False
    
    def is_device_or_ip_identifier(self, value_str):
        """
        Detect device IDs or IP addresses that can identify users
        """
        if not value_str:
            return False
            
        value_clean = str(value_str).strip()
        
        # IP address pattern (IPv4)
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, value_clean):
            # Validate IP ranges
            parts = value_clean.split('.')
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
                
        # Device ID patterns (various formats)
        device_patterns = [
            r'^[A-Z0-9]{8,}$',      # Alphanumeric device IDs
            r'^DEV\d+$',           # DEV followed by numbers
            r'^[A-Z]+\d+$',        # Letters followed by numbers
        ]
        
        for pattern in device_patterns:
            if re.match(pattern, value_clean.upper()):
                return True
                
        return False
    
    def apply_masking_strategy(self, pii_type, value):
        """
        Apply appropriate masking based on PII type and data sensitivity
        """
        value_str = self.normalize_json_value(value)
        
        if pii_type == 'phone':
            return self._mask_phone_number(value_str)
        elif pii_type == 'aadhar':
            return self._mask_aadhar_number(value_str)
        elif pii_type == 'passport':
            return self._mask_passport_number(value_str)
        elif pii_type == 'upi_id':
            return self._mask_upi_id(value_str)
        elif pii_type == 'email':
            return self._mask_email_address(value_str)
        elif pii_type == 'name':
            return self._mask_full_name(value_str)
        elif pii_type == 'address':
            return self._mask_address(value_str)
        elif pii_type == 'device_id':
            return self._mask_device_id(value_str)
        elif pii_type == 'ip_address':
            return self._mask_ip_address(value_str)
        
        return value_str
    
    def _mask_phone_number(self, phone):
        """Mask phone: 98XXXXXX10"""
        digits = re.sub(r'\D', '', str(phone))
        if len(digits) == 10:
            return f"{digits[:2]}XXXXXX{digits[-2:]}"
        return digits
    
    def _mask_aadhar_number(self, aadhar):
        """Mask Aadhar: XXXX XXXX 9012"""
        digits = re.sub(r'\D', '', str(aadhar))
        if len(digits) == 12:
            return f"XXXX XXXX {digits[-4:]}"
        return digits
    
    def _mask_passport_number(self, passport):
        """Mask passport: PXXXXXXX"""
        passport_str = str(passport).upper()
        if len(passport_str) >= 2:
            return f"{passport_str[0]}{'X' * (len(passport_str) - 1)}"
        return 'XXXXXXXX'
    
    def _mask_upi_id(self, upi):
        """Mask UPI: uXXX@provider"""
        if '@' in str(upi):
            username, provider = str(upi).split('@', 1)
            masked_user = username[0] + 'X' * max(0, len(username) - 1) if username else 'X'
            return f"{masked_user}@{provider}"
        return str(upi)
    
    def _mask_email_address(self, email):
        """Mask email: rXXXXX@domain.com"""
        if '@' in str(email):
            username, domain = str(email).split('@', 1)
            masked_user = username[0] + 'X' * max(0, len(username) - 1) if username else 'X'
            return f"{masked_user}@{domain}"
        return str(email)
    
    def _mask_full_name(self, name):
        """Mask name: JXXX SXXXX"""
        words = str(name).split()
        masked_words = []
        for word in words:
            if len(word) > 1:
                masked_words.append(word[0].upper() + 'X' * (len(word) - 1))
            else:
                masked_words.append('X')
        return ' '.join(masked_words)
    
    def _mask_address(self, address):
        """Mask address while preserving structure"""
        parts = [part.strip() for part in str(address).split(',')]
        masked_parts = []
        
        for part in parts:
            words = part.split()
            masked_words = []
            for word in words:
                if re.match(r'^\d+$', word):  # Pure numbers (like pincodes)
                    masked_words.append('X' * len(word))
                elif len(word) > 2:
                    masked_words.append(word[:1] + 'X' * (len(word) - 1))
                else:
                    masked_words.append('X' * len(word))
            masked_parts.append(' '.join(masked_words))
            
        return ', '.join(masked_parts)
    
    def _mask_device_id(self, device_id):
        """Mask device ID: DEVXXXXX"""
        device_str = str(device_id)
        if len(device_str) > 3:
            return device_str[:3] + 'X' * (len(device_str) - 3)
        return 'X' * len(device_str)
    
    def _mask_ip_address(self, ip):
        """Mask IP: XXX.XXX.XXX.100"""
        if '.' in str(ip):
            parts = str(ip).split('.')
            if len(parts) == 4:
                return f"XXX.XXX.XXX.{parts[-1]}"
        return 'XXX.XXX.XXX.XXX'
    
    def analyze_record_for_pii(self, record_dict):
        """
        Comprehensive PII analysis for a single record
        Returns: (has_pii: bool, redacted_record: dict)
        """
        has_pii = False
        redacted_record = {}
        pii_found = []
        
        # Step 1: Check for standalone PII
        standalone_pii_detected = {}
        for key, value in record_dict.items():
            normalized_value = self.normalize_json_value(value)
            
            # Direct field name matching for known PII fields
            if key == 'phone' or self.is_valid_phone_number(normalized_value):
                standalone_pii_detected[key] = 'phone'
                has_pii = True
                pii_found.append(f"Phone: {key}")
                
            elif key == 'aadhar' or self.is_valid_aadhar(normalized_value):
                standalone_pii_detected[key] = 'aadhar'
                has_pii = True
                pii_found.append(f"Aadhar: {key}")
                
            elif key == 'passport' or self.is_valid_passport(normalized_value):
                standalone_pii_detected[key] = 'passport'
                has_pii = True
                pii_found.append(f"Passport: {key}")
                
            elif key == 'upi_id' or self.is_valid_upi_id(normalized_value):
                standalone_pii_detected[key] = 'upi_id'
                has_pii = True
                pii_found.append(f"UPI ID: {key}")
        
        # Step 2: Check for combinatorial PII
        combinatorial_elements = {}
        for key, value in record_dict.items():
            normalized_value = self.normalize_json_value(value)
            
            if key == 'name' and self.is_full_name(normalized_value):
                combinatorial_elements[key] = 'name'
                
            elif key == 'email' and self.is_valid_email(normalized_value):
                combinatorial_elements[key] = 'email'
                
            elif key == 'address' and self.is_complete_address(normalized_value):
                combinatorial_elements[key] = 'address'
                
            elif key in ['device_id', 'ip_address'] and self.is_device_or_ip_identifier(normalized_value):
                combinatorial_elements[key] = key
        
        # Evaluate combinatorial PII rules
        combinatorial_pii_detected = {}
        combinatorial_count = len([k for k, v in combinatorial_elements.items() 
                                 if v in ['name', 'email', 'address']])
        
        if combinatorial_count >= 2:
            # Two or more combinatorial elements = PII
            has_pii = True
            combinatorial_pii_detected.update(combinatorial_elements)
            pii_found.append(f"Combinatorial PII: {list(combinatorial_elements.keys())}")
            
        elif combinatorial_count >= 1 and any(k in ['device_id', 'ip_address'] for k in combinatorial_elements):
            # One combinatorial + device/IP = PII
            has_pii = True
            combinatorial_pii_detected.update(combinatorial_elements)
            pii_found.append(f"Combinatorial + Device/IP PII: {list(combinatorial_elements.keys())}")
        
        # Step 3: Apply redaction
        all_pii_fields = {**standalone_pii_detected, **combinatorial_pii_detected}
        
        for key, value in record_dict.items():
            if key in all_pii_fields:
                pii_type = all_pii_fields[key]
                redacted_record[key] = self.apply_masking_strategy(pii_type, value)
            else:
                redacted_record[key] = value
        
        return has_pii, redacted_record
    
    def process_csv_dataset(self, input_file_path, output_file_path):
        """
        Process the complete CSV dataset for PII detection and redaction
        """
        try:
            # Load the dataset
            print(f"Loading dataset from {input_file_path}...")
            df = pd.read_csv(input_file_path)
            print(f"Loaded {len(df)} records")
            
            results = []
            processing_stats = {
                'total_records': len(df),
                'pii_records': 0,
                'clean_records': 0,
                'processing_errors': 0
            }
            
            # Process each record
            for idx, row in df.iterrows():
                try:
                    record_id = row['record_id']
                    json_data = row['data_json']
                    
                    # Parse JSON data
                    record_dict = json.loads(json_data)
                    
                    # Analyze for PII
                    has_pii, redacted_record = self.analyze_record_for_pii(record_dict)
                    
                    # Update statistics
                    if has_pii:
                        processing_stats['pii_records'] += 1
                    else:
                        processing_stats['clean_records'] += 1
                    
                    # Prepare output record
                    results.append({
                        'record_id': record_id,
                        'redacted_data_json': json.dumps(redacted_record, ensure_ascii=False),
                        'is_pii': has_pii
                    })
                    
                    # Progress indicator
                    if (idx + 1) % 100 == 0:
                        print(f"Processed {idx + 1}/{len(df)} records...")
                        
                except Exception as e:
                    print(f"Error processing record {row.get('record_id', idx)}: {str(e)}")
                    processing_stats['processing_errors'] += 1
                    
                    # Add error record to maintain data integrity
                    results.append({
                        'record_id': row.get('record_id', idx),
                        'redacted_data_json': row.get('data_json', '{}'),
                        'is_pii': False  # Conservative approach for errors
                    })
            
            # Create output DataFrame and save
            output_df = pd.DataFrame(results)
            output_df.to_csv(output_file_path, index=False)
            
            # Print final statistics
            print(f"\nProcessing Complete!")
            print(f"Total Records: {processing_stats['total_records']}")
            print(f"PII Records: {processing_stats['pii_records']}")
            print(f"Clean Records: {processing_stats['clean_records']}")
            print(f"Processing Errors: {processing_stats['processing_errors']}")
            print(f"Output saved to: {output_file_path}")
            
            return processing_stats
            
        except Exception as e:
            print(f"Fatal error during processing: {str(e)}")
            raise

def main():
    """Main execution function with command line argument handling"""
    if len(sys.argv) != 2:
        print("Usage: python3 detector_Gaja_sagar.py iscp_pii_dataset_-_Sheet1.csv")
        print("Example: python3 detector_Gaja_sagar.py iscp_pii_dataset_-_Sheet1.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # Validate input file
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    
    # Generate output filename
    base_name = os.path.splitext(input_file)[0]
    output_file = f"redacted_output_Gaja_sagar.csv"
    
    print("=== PII Detection and Redaction System ===")
    print(f"Input File: {input_file}")
    print(f"Output File: {output_file}")
    print("="*50)
    
    # Initialize detector and process dataset
    detector = PIIDetectorRedactor()
    
    try:
        stats = detector.process_csv_dataset(input_file, output_file)
        print("\nPII detection and redaction completed successfully!")
        
    except Exception as e:
        print(f"\nFailed to process dataset: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
