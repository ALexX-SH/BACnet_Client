#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BACnet Client
Client for reading data from BACnet device and displaying on web server
With support for BACnet/SC (BACnet Secure Connect), BBMD, COV and TrendLog for Automated Logic controllers
"""

import socket
import struct
import time
import logging
import binascii
import threading
import configparser
import json
import signal
import sys
import os
import math
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Tuple, Union, Any


# For BACnet/SC support
try:
    import ssl
    import websockets
    import asyncio
    import uuid
    import hashlib
    import base64
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    BACNET_SC_AVAILABLE = True
except ImportError:
    BACNET_SC_AVAILABLE = False
    print("WARNING: Some BACnet/SC dependencies are not installed.")
    print("BACnet/SC support will be disabled.")
    print("To enable BACnet/SC, install required packages: pip install websockets cryptography")

# Try to import scapy for packet capturing
try:
    from scapy.all import sniff, Ether, IP, UDP, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy is not installed. Packet capture will not be available.")
    print("To install scapy: pip install scapy")


# Logging setup
logs_dir = "logs"
if not os.path.exists(logs_dir):
    os.makedirs(logs_dir)

log_file_path = os.path.join(logs_dir, "co2_bacnet_client.log")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file_path, mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('bacnet_client')
logger.setLevel(logging.DEBUG)

logger.info(f"Logging to file: {os.path.abspath(log_file_path)}")
logger.info("BACnet client logger initialized")

# -------------- BACnet Constants --------------

# APDU Types
APDU_CONFIRMED_REQ = 0x00
APDU_UNCONFIRMED_REQ = 0x10
APDU_SIMPLE_ACK = 0x20
APDU_COMPLEX_ACK = 0x30
APDU_SEGMENT_ACK = 0x40
APDU_ERROR = 0x50
APDU_REJECT = 0x60
APDU_ABORT = 0x70
APDU_CONFIRMED_RES = 0x30  # In most cases, ComplexAck is used as ConfirmedResponse
                           

# NPDU Control Flags
NPDU_PRIORITY_NORMAL = 0
NPDU_PRIORITY_URGENT = 1
NPDU_PRIORITY_CRITICAL = 2
NPDU_PRIORITY_LIFE_SAFETY = 3
NPDU_NETWORK_MESSAGE = 0x80
NPDU_DEST_PRESENT = 0x20
NPDU_SRC_PRESENT = 0x08
NPDU_EXPECTING_REPLY = 0x04

# Service Choice - Unconfirmed
SERVICE_UNCONFIRMED_I_AM = 0
SERVICE_UNCONFIRMED_WHO_IS = 8
SERVICE_UNCONFIRMED_COV_NOTIFICATION = 2
SERVICE_UNCONFIRMED_TIME_SYNCHRONIZATION = 6
SERVICE_UNCONFIRMED_UTC_TIME_SYNCHRONIZATION = 9

# Service Choice - Confirmed
SERVICE_CONFIRMED_READ_PROPERTY = 12
SERVICE_CONFIRMED_WRITE_PROPERTY = 15
SERVICE_CONFIRMED_READ_PROPERTY_MULTIPLE = 14
SERVICE_CONFIRMED_WRITE_PROPERTY_MULTIPLE = 16
SERVICE_CONFIRMED_READ_RANGE = 26
SERVICE_CONFIRMED_SUBSCRIBE_COV = 5
SERVICE_CONFIRMED_SUBSCRIBE_COV_PROPERTY = 28
SERVICE_CONFIRMED_GET_EVENT_INFORMATION = 29
SERVICE_CONFIRMED_ACKNOWLEDGE_ALARM = 0

# BVLC Function Codes
BVLC_RESULT = 0x00
BVLC_WRITE_BROADCAST_DISTRIBUTION_TABLE = 0x01
BVLC_READ_BROADCAST_DIST_TABLE = 0x02
BVLC_READ_BROADCAST_DIST_TABLE_ACK = 0x03
BVLC_FORWARDED_NPDU = 0x04
BVLC_REGISTER_FOREIGN_DEVICE = 0x05
BVLC_READ_FOREIGN_DEVICE_TABLE = 0x06
BVLC_READ_FOREIGN_DEVICE_TABLE_ACK = 0x07
BVLC_DELETE_FOREIGN_DEVICE_TABLE_ENTRY = 0x08
BVLC_DISTRIBUTE_BROADCAST_TO_NETWORK = 0x09
BVLC_ORIGINAL_UNICAST_NPDU = 0x0A
BVLC_ORIGINAL_BROADCAST_NPDU = 0x0B
BVLC_SECURE_BVLL = 0x0C

# Object Types
OBJECT_DEVICE = 8
OBJECT_ANALOG_INPUT = 0
OBJECT_ANALOG_OUTPUT = 1
OBJECT_ANALOG_VALUE = 2
OBJECT_BINARY_INPUT = 3
OBJECT_BINARY_OUTPUT = 4
OBJECT_BINARY_VALUE = 5
OBJECT_MULTI_STATE_INPUT = 13
OBJECT_MULTI_STATE_OUTPUT = 14
OBJECT_MULTI_STATE_VALUE = 19
OBJECT_TRENDLOG = 20
OBJECT_NOTIFICATION_CLASS = 15
OBJECT_SCHEDULE = 17
OBJECT_CALENDAR = 6
OBJECT_PROGRAM = 16
OBJECT_FILE = 10

# Property IDs
PROP_OBJECT_IDENTIFIER = 75
PROP_OBJECT_NAME = 77
PROP_OBJECT_TYPE = 79
PROP_PRESENT_VALUE = 85
PROP_DESCRIPTION = 28
PROP_DEVICE_TYPE = 31
PROP_FIRMWARE_REVISION = 44
PROP_LOCATION = 58
PROP_MODEL_NAME = 70
PROP_VENDOR_NAME = 121
PROP_VENDOR_IDENTIFIER = 120
PROP_PROTOCOL_VERSION = 98
PROP_PROTOCOL_REVISION = 139
PROP_PROTOCOL_SERVICES_SUPPORTED = 97
PROP_PROTOCOL_OBJECT_TYPES_SUPPORTED = 96
PROP_OBJECT_LIST = 76
PROP_MAX_APDU_LENGTH_ACCEPTED = 62
PROP_SEGMENTATION_SUPPORTED = 107
PROP_UNITS = 117
PROP_APPLICATION_SOFTWARE_VERSION = 12
PROP_LOG_BUFFER = 131
PROP_RECORD_COUNT = 141
PROP_TOTAL_RECORD_COUNT = 145
PROP_START_TIME = 142
PROP_STOP_TIME = 143
PROP_LOGGING_TYPE = 72
PROP_STATUS_FLAGS = 111
PROP_RELIABILITY = 103
PROP_OUT_OF_SERVICE = 81
PROP_NOTIFICATION_CLASS = 17
PROP_EVENT_ENABLE = 35
PROP_NOTIFY_TYPE = 72

# Application Tags
BACNET_APPLICATION_TAG_NULL = 0
BACNET_APPLICATION_TAG_BOOLEAN = 1
BACNET_APPLICATION_TAG_UNSIGNED = 2
BACNET_APPLICATION_TAG_SIGNED = 3
BACNET_APPLICATION_TAG_REAL = 4
BACNET_APPLICATION_TAG_DOUBLE = 5
BACNET_APPLICATION_TAG_OCTET_STRING = 6
BACNET_APPLICATION_TAG_CHARACTER_STRING = 7
BACNET_APPLICATION_TAG_BIT_STRING = 8
BACNET_APPLICATION_TAG_ENUMERATED = 9
BACNET_APPLICATION_TAG_DATE = 10
BACNET_APPLICATION_TAG_TIME = 11
BACNET_APPLICATION_TAG_OBJECT_ID = 12

# BACnet Error Classes
BACNET_ERROR_CLASS_DEVICE = 0
BACNET_ERROR_CLASS_OBJECT = 1
BACNET_ERROR_CLASS_PROPERTY = 2
BACNET_ERROR_CLASS_RESOURCES = 3
BACNET_ERROR_CLASS_SECURITY = 4
BACNET_ERROR_CLASS_SERVICES = 5
BACNET_ERROR_CLASS_VT = 6
BACNET_ERROR_CLASS_COMMUNICATION = 7

# BACnet Error Codes
BACNET_ERROR_CODE_OTHER = 0
BACNET_ERROR_CODE_INVALID_VALUE = 37
BACNET_ERROR_CODE_UNKNOWN_OBJECT = 31
BACNET_ERROR_CODE_UNKNOWN_PROPERTY = 32
BACNET_ERROR_CODE_UNSUPPORTED_OBJECT_TYPE = 36


# Dictionaries for human-readable names
BACNET_OBJECT_TYPES = {
    OBJECT_ANALOG_INPUT: "Analog Input",
    OBJECT_ANALOG_OUTPUT: "Analog Output",
    OBJECT_ANALOG_VALUE: "Analog Value",
    OBJECT_BINARY_INPUT: "Binary Input",
    OBJECT_BINARY_OUTPUT: "Binary Output",
    OBJECT_BINARY_VALUE: "Binary Value",
    OBJECT_DEVICE: "Device",
    OBJECT_MULTI_STATE_INPUT: "Multi-State Input",
    OBJECT_MULTI_STATE_OUTPUT: "Multi-State Output",
    OBJECT_MULTI_STATE_VALUE: "Multi-State Value",
    OBJECT_TRENDLOG: "Trend Log",
    OBJECT_NOTIFICATION_CLASS: "Notification Class",
    OBJECT_SCHEDULE: "Schedule",
    OBJECT_CALENDAR: "Calendar",
    OBJECT_PROGRAM: "Program",
    OBJECT_FILE: "File"
}

BACNET_PROPERTY_NAMES = {
    PROP_OBJECT_IDENTIFIER: "Object Identifier",
    PROP_OBJECT_NAME: "Object Name",
    PROP_OBJECT_TYPE: "Object Type",
    PROP_PRESENT_VALUE: "Present Value",
    PROP_DESCRIPTION: "Description",
    PROP_DEVICE_TYPE: "Device Type",
    PROP_FIRMWARE_REVISION: "Firmware Revision",
    PROP_LOCATION: "Location",
    PROP_MODEL_NAME: "Model Name",
    PROP_VENDOR_NAME: "Vendor Name",
    PROP_VENDOR_IDENTIFIER: "Vendor Identifier",
    PROP_PROTOCOL_VERSION: "Protocol Version",
    PROP_PROTOCOL_REVISION: "Protocol Revision",
    PROP_PROTOCOL_SERVICES_SUPPORTED: "Protocol Services Supported",
    PROP_PROTOCOL_OBJECT_TYPES_SUPPORTED: "Protocol Object Types Supported",
    PROP_OBJECT_LIST: "Object List",
    PROP_MAX_APDU_LENGTH_ACCEPTED: "Max APDU Length Accepted",
    PROP_SEGMENTATION_SUPPORTED: "Segmentation Supported",
    PROP_UNITS: "Units",
    PROP_APPLICATION_SOFTWARE_VERSION: "Application Software Version",
    PROP_LOG_BUFFER: "Log Buffer",
    PROP_RECORD_COUNT: "Record Count",
    PROP_TOTAL_RECORD_COUNT: "Total Record Count",
    PROP_START_TIME: "Start Time",
    PROP_STOP_TIME: "Stop Time",
    PROP_LOGGING_TYPE: "Logging Type",
    PROP_STATUS_FLAGS: "Status Flags",
    PROP_RELIABILITY: "Reliability",
    PROP_OUT_OF_SERVICE: "Out of Service",
    PROP_NOTIFICATION_CLASS: "Notification Class",
    PROP_EVENT_ENABLE: "Event Enable",
    PROP_NOTIFY_TYPE: "Notify Type"
}

BACNET_ERROR_CLASSES = {
    BACNET_ERROR_CLASS_DEVICE: "Device",
    BACNET_ERROR_CLASS_OBJECT: "Object",
    BACNET_ERROR_CLASS_PROPERTY: "Property",
    BACNET_ERROR_CLASS_RESOURCES: "Resources",
    BACNET_ERROR_CLASS_SECURITY: "Security",
    BACNET_ERROR_CLASS_SERVICES: "Services",
    BACNET_ERROR_CLASS_VT: "VT",
    BACNET_ERROR_CLASS_COMMUNICATION: "Communication"
}

BACNET_ERROR_CODES = {
    BACNET_ERROR_CODE_OTHER: "Other",
    BACNET_ERROR_CODE_INVALID_VALUE: "Invalid Value",
    BACNET_ERROR_CODE_UNKNOWN_OBJECT: "Unknown Object",
    BACNET_ERROR_CODE_UNKNOWN_PROPERTY: "Unknown Property",
    BACNET_ERROR_CODE_UNSUPPORTED_OBJECT_TYPE: "Unsupported Object Type"
}


# Global variables for storing data
current_value = 0.0
current_description = "CO2.A.PIECE"
current_object_name = "co2_a_piece_1"
discovered_devices = {}
discovered_objects = {}
last_update_time = datetime.now()
client_running = True
client_instance = None
packet_capture_running = False
invoke_id_to_request_map = {}
invoke_id_counter = 0


# ----------------- Helper Functions -----------------
def object_type_to_name(object_type: int) -> str:
   
    """Converts numeric object type to human-readable name"""
    return BACNET_OBJECT_TYPES.get(object_type, f"Unknown({object_type})")

def property_id_to_name(property_id: int) -> str:
    
    """Converts numeric property ID to human-readable name"""
    return BACNET_PROPERTY_NAMES.get(property_id, f"Property_{property_id}")


# ----------------- BACnet Client Class -----------------
class BACnetClient:
    
    """Client for BACnet communication supporting various BACnet protocol features"""
    
    def __init__(self, config: configparser.ConfigParser):
        """
        Initialize the BACnet client
        
        Args:
            config: Client configuration from configparser
        """
       
        # Save a reference to the configuration object
        self.config = config
        
        
        # IP address and port of the BACnet server
        self.server_ip = config.get('Network', 'target_ip')
        self.server_port = int(config.get('Network', 'target_port'))
        
        
        # Local IP address and port for communication
        self.local_ip = config.get('Network', 'local_ip')
        self.local_port = int(config.get('Network', 'local_port'))
        
        self.device_id = int(config.get('BACNet_Device', 'device_id'))
        self.analog_input_instance = int(config.get('BACNet_Device', 'analog_input_instance'))
        
        
        # Variable to store the last original value (before endianness correction)
        self.last_original_value = None
        self.invoke_id = 0
        
        
        # Create a UDP socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        
        # Set socket options
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        
        # Bind to local address and port
        try:
            self.socket.bind((self.local_ip, self.local_port))
            logger.info(f"Socket bound to {self.local_ip}:{self.local_port}")
        except Exception as e:
            logger.error(f"Error binding socket: {e}")
            
            # Try another port
            fallback_port = self.local_port + 1
            try:
                self.socket.bind((self.local_ip, fallback_port))
                self.local_port = fallback_port
                logger.info(f"Socket bound to fallback port {self.local_ip}:{self.local_port}")
            except Exception as e2:
                logger.error(f"Error binding to fallback port: {e2}")
                raise
        
        logger.info(f"BACnet client initialized. Target server: {self.server_ip}:{self.server_port}")
        
        
        # Save the use_broadcast parameter
        try:
            self.use_broadcast = config.getboolean('Network', 'UseBroadcast', fallback=True)
        except:
            self.use_broadcast = True
        
        logger.info(f"Broadcast mode: {'enabled' if self.use_broadcast else 'disabled'}")
        
        
        # Check if registration with BBMD is needed
        try:
            self.use_bbmd = config.getboolean('Network', 'UseBBMD', fallback=False)
            if self.use_bbmd:
                self.bbmd_address = config.get('Network', 'BBMDAddress', fallback=self.server_ip)
                self.bbmd_port = int(config.get('Network', 'BBMDPort', fallback=self.server_port))
                self.bbmd_ttl = int(config.get('Network', 'BBMDTTL', fallback=1800))  
                                                                                     # Default 30 minutes
                
                logger.info(f"BBMD mode enabled: {self.bbmd_address}:{self.bbmd_port}, TTL: {self.bbmd_ttl}")
                self.register_foreign_device(self.bbmd_address, self.bbmd_port, self.bbmd_ttl)
        except Exception as e:
            logger.warning(f"BBMD configuration error: {e}")
            self.use_bbmd = False
    
    def __del__(self):
        
        """Destructor for proper resource release"""
        if hasattr(self, 'socket'):
            self.socket.close()
    
    def register_foreign_device(self, bbmd_address: str, bbmd_port: int = 47808, ttl: int = 1800) -> bool:
        """
        Register the client as a Foreign Device in BBMD
        
        Args:
            bbmd_address: IP address of BBMD
            bbmd_port: BBMD port (default 47808)
            ttl: Registration lifetime in seconds (default 1800 = 30 minutes)
            
        Returns:
            bool: True if registration is successful
        """
        logger.info(f"Registering as foreign device to BBMD at {bbmd_address}:{bbmd_port} with TTL {ttl}")
        
        
        # Build the Foreign Device registration packet
        
        # BVLL Type: 0x81 (BVLC for BACnet/IP)
        # Function: 0x05 (Register-Foreign-Device)
        
        # BVLC Length: 6 (2 bytes)
        
        # TTL: 2 bytes (registration lifetime)
        
        
        # Convert TTL to network byte order (big-endian)
        ttl_bytes = struct.pack('>H', ttl)
        
        
        # Form the complete packet
        packet = bytearray([0x81, BVLC_REGISTER_FOREIGN_DEVICE, 0x00, 0x06]) + ttl_bytes
        
        try:
            
            # Send the packet to BBMD
            self.socket.sendto(packet, (bbmd_address, bbmd_port))
            logger.info(f"Sent Register-Foreign-Device to {bbmd_address}:{bbmd_port}")
            
            
            # Wait for registration confirmation
            self.socket.settimeout(5)  
                                       # Timeout 5 seconds
            
            try:
                data, addr = self.socket.recvfrom(1024)
                
                
                # Check if this is a response to registration
                if len(data) >= 4 and data[0] == 0x81 and data[1] == BVLC_RESULT:
                    
                    # Get the result code (should be 0x0000 for success)
                    result_code = struct.unpack('>H', data[4:6])[0] if len(data) >= 6 else -1
                    
                    if result_code == 0:
                        logger.info("Successfully registered as foreign device")
                        
                        
                        # Start a thread for periodic registration renewal
                        self.bbmd_address = bbmd_address
                        self.bbmd_port = bbmd_port
                        self.bbmd_ttl = ttl
                        
                        
                        # Create a timer that will trigger re-registration
                        
                        # approximately 1 minute before TTL expires
                        refresh_seconds = max(60, ttl - 60)  
                                                             # No less than 60 seconds
                        threading.Timer(refresh_seconds, self.refresh_foreign_device_registration).start()
                        
                        return True
                    else:
                        logger.error(f"Foreign device registration failed, result code: {result_code}")
                        return False
                else:
                    logger.warning(f"Unexpected response to foreign device registration: {binascii.hexlify(data).decode('ascii')}")
                    return False
                    
            except socket.timeout:
                logger.error("Timeout waiting for foreign device registration response")
                return False
                
        except Exception as e:
            logger.error(f"Error registering as foreign device: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
        finally:
            
            # Reset socket timeout
            self.socket.settimeout(None)
    
    def refresh_foreign_device_registration(self) -> None:
        """Refreshes the registration in BBMD before TTL expires"""
        logger.debug("Refreshing foreign device registration")
        
        if hasattr(self, 'bbmd_address') and hasattr(self, 'bbmd_port') and hasattr(self, 'bbmd_ttl'):
            
            # Attempt to refresh the registration
            success = self.register_foreign_device(self.bbmd_address, self.bbmd_port, self.bbmd_ttl)
            
            if not success:
                
                # If failed, try again in one minute
                logger.warning("Failed to refresh foreign device registration, will retry in 60 seconds")
                threading.Timer(60, self.refresh_foreign_device_registration).start()
        else:
            logger.warning("Cannot refresh foreign device registration - BBMD parameters not available")
    
    def close(self) -> None:
        """Closes the BACnet client properly"""
        if hasattr(self, 'socket'):
            self.socket.close()
            logger.info("BACnet client socket closed")
    
    def get_invoke_id(self) -> int:
        """Generates a new invoke ID for confirmed requests"""
        self.invoke_id = (self.invoke_id + 1) % 256
        return self.invoke_id
    
    def build_bvlc_header(self, function_code: int, payload_length: int) -> bytes:
        """
        Builds the BVLC (BACnet Virtual Link Control) header
        
        Args:
            function_code: BVLC function code
            payload_length: Length of the payload in bytes
            
        Returns:
            bytes: BVLC header
        """
        # BVLC Type (0x81) + Function Code + Length (including BVLC header)
        total_length = payload_length + 4  # 4 bytes for BVLC header
        return struct.pack('!BBH', 0x81, function_code, total_length)
    
    def build_npdu(self, destination: Optional[bytes] = None, 
                   expecting_reply: bool = True, 
                   priority: int = NPDU_PRIORITY_NORMAL) -> bytes:
        """
        Builds the NPDU (Network Protocol Data Unit) header
        
        Args:
            destination: Bytes of the destination network address (if needed)
            expecting_reply: Whether a reply is expected
            priority: Message priority
            
        Returns:
            bytes: NPDU header
        """
        if destination:
            # With destination network address
            control = NPDU_DEST_PRESENT  # Set destination bit
            if expecting_reply:
                control |= NPDU_EXPECTING_REPLY  # Set expecting reply bit
            
            # Add priority bits
            control |= (priority & 0x03)
            
            # NPDU with destination
            # Version(1) + Control + DNET + DLEN + DADR + HOP
            return struct.pack('!BB', 0x01, control) + destination
        else:
            # Without destination (broadcast)
            control = 0x00
            if expecting_reply:
                control |= NPDU_EXPECTING_REPLY  # Set expecting reply bit
            
            # Add priority bits
            control |= (priority & 0x03)
            
            # NPDU without destination
            # Version(1) + Control
            return struct.pack('!BB', 0x01, control)
    
    def build_apdu_header(self, apdu_type: int, service_choice: int, 
                          invoke_id: Optional[int] = None, 
                          segmentation: int = 0) -> Optional[bytes]:
        """
        Builds the APDU (Application Protocol Data Unit) header
        
        Args:
            apdu_type: APDU type (e.g., APDU_CONFIRMED_REQ)
            service_choice: BACnet service code
            invoke_id: Request ID for response tracking (for confirmed requests)
            segmentation: Segmentation flags
            
        Returns:
            bytes: APDU header
        """
        if apdu_type == APDU_CONFIRMED_REQ:
            # PDU Type + Segmentation + Max Response + Invoke ID + Service Choice
            max_segments = 0x00  # No segmentation
            max_apdu = 0x05      # Max APDU size 1476 bytes
            segmentation_control = (max_segments << 4) | max_apdu
            return struct.pack('!BBBB', apdu_type, segmentation_control, invoke_id, service_choice)
        elif apdu_type == APDU_UNCONFIRMED_REQ:
            # PDU Type + Service Choice
            return struct.pack('!BB', apdu_type, service_choice)
        else:
            logger.error(f"Unsupported APDU type: {apdu_type}")
            return None
    
    def encode_tag(self, tag_number: int, context_specific: bool, 
                  data: Optional[bytes] = None, 
                  data_length: Optional[int] = None) -> bytes:
        """
        Encodes a BACnet tag
        
        Args:
            tag_number: Номер тега
            context_specific: Является ли тег контекстно-зависимым
            data: Данные тега (если есть)
            data_length: Длина данных (если не указана, рассчитывается автоматически)
            
        Returns:
            bytes: Закодированный тег
        """
        first_octet = 0
        if context_specific:
            first_octet |= 0x08  # Set context specific bit
        
        if data is None:
            # Opening or closing tag
            first_octet |= 0x06  # Set opening/closing tag bit
            if tag_number <= 14:
                return bytes([first_octet | tag_number])
            else:
                return bytes([first_octet | 0x0F, tag_number])
        else:
            # Value tag
            if data_length is None:
                data_length = len(data)
            
            if data_length <= 4:
                first_octet |= data_length
            else:
                first_octet |= 0x05  # Extended length
            
            if tag_number <= 14:
                result = bytes([first_octet | tag_number])
            else:
                result = bytes([first_octet | 0x0F, tag_number])
            
            if data_length <= 4:
                result += data
            else:
                result += struct.pack('!B', data_length) + data
            
            return result
    
    def encode_unsigned(self, value: int) -> bytes:
        """
        Кодирует беззнаковое целое число в байты
        
        Args:
            value: Целое число для кодирования
            
        Returns:
            bytes: Закодированное число
        """
        if value < 0x100:
            return struct.pack('!B', value)
        elif value < 0x10000:
            return struct.pack('!H', value)
        elif value < 0x1000000:
            return struct.pack('!BH', (value >> 16) & 0xFF, value & 0xFFFF)
        else:
            return struct.pack('!L', value)
    
    def encode_object_id(self, object_type: int, instance: int) -> bytes:
        """
        Кодирует идентификатор объекта BACnet
        
        Args:
            object_type: Тип объекта
            instance: Экземпляр объекта
            
        Returns:
            bytes: Закодированный идентификатор объекта
        """
        object_id = ((object_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
        return struct.pack('!L', object_id)
    
    def search_ieee754_values(self, raw_bytes: bytes) -> Tuple[float, float, bool]:
        """
        Search for IEEE754 values within a packet for debugging purposes.
        This version prioritizes big-endian for Automatic Logic and handles specific patterns.

        Args:
            raw_bytes: The byte sequence of the packet to search within.

        Returns:
            tuple: (corrected_value, original_big_endian_value, found_value_flag)
                   original_big_endian_value is always the big-endian interpretation if found.
        """
        # Log the entire packet for debugging
        logger.debug(f"IEEE754 Raw response: {binascii.hexlify(raw_bytes).decode('ascii')}")

        # Potential 4-byte sequences to check
        data_to_check = []

        # If the data length is exactly 4 bytes, use it directly
        if len(raw_bytes) == 4:
            data_to_check.append(raw_bytes)
            logger.debug(f"Using direct 4 bytes: {binascii.hexlify(raw_bytes).decode('ascii')}")
        else:
            # Special check for the Automatic Logic pattern: 3E44XXXX3F
            al_pattern_found = False
            for i in range(len(raw_bytes) - 7):
                # Check for the start (3E 44) and end (3F) tags with 4 bytes in between
                if (raw_bytes[i] == 0x3E and
                        raw_bytes[i+1] == 0x44 and
                        raw_bytes[i+6] == 0x3F):
                    real_bytes = raw_bytes[i+2:i+6]  # Extract the 4 bytes for the REAL value
                    data_to_check.append(real_bytes)
                    logger.debug(f"Found Automatic Logic pattern 3E44XXXX3F, extracted bytes: {binascii.hexlify(real_bytes).decode('ascii')}")
                    al_pattern_found = True
                    # If this is the specific 'disconnected sensor' value for Automatic Logic
                    if real_bytes == b'\xc4\x9c\x0f\x0a':
                        logger.info(f"Found exact pattern for disconnected Automatic Logic sensor: c49c0f0a = -1248.47")
                        # Return the known value directly
                        return -1248.47, -1248.47, True
                    # Prioritize the value found within this pattern
                    break # Stop searching once the AL pattern is found and processed

            # If the AL pattern wasn't found, look for other potential REAL values
            if not al_pattern_found:
                for i in range(len(raw_bytes) - 4):
                    # Look for the REAL tag (0x44) and take the following 4 bytes
                    # Ensure we don't re-add bytes if they were already added via the AL pattern check (although break prevents this)
                    if raw_bytes[i] == 0x44 and (i+1+4) <= len(raw_bytes):
                        potential_bytes = raw_bytes[i+1:i+5]
                        if potential_bytes not in data_to_check:
                            data_to_check.append(potential_bytes)
                            logger.debug(f"Found potential REAL value after 0x44 tag: {binascii.hexlify(potential_bytes).decode('ascii')}")

                # Check if the packet ends with a closing context tag (0x3F), potentially indicating a preceding REAL value
                if len(raw_bytes) >= 5 and raw_bytes[-1] == 0x3F:
                    potential_bytes = raw_bytes[-5:-1]
                    if potential_bytes not in data_to_check:
                         data_to_check.append(potential_bytes)
                         logger.debug(f"Found potential REAL value before closing tag 0x3F: {binascii.hexlify(potential_bytes).decode('ascii')}")

            # If still no candidates found, try using the last 4 bytes as a fallback
            if not data_to_check and len(raw_bytes) >= 4:
                potential_bytes = raw_bytes[-4:]
                data_to_check.append(potential_bytes)
                logger.debug(f"Using last 4 bytes as fallback: {binascii.hexlify(potential_bytes).decode('ascii')}")

        # Iterate through all found 4-byte candidates
        for check_bytes in data_to_check:
            try:
                # Explicit check for the known disconnected sensor pattern
                if check_bytes == b'\xc4\x9c\x0f\x0a':
                    logger.info(f"Identified exact pattern for disconnected sensor: c49c0f0a = -1248.47")
                    # Return the specific value, using it as both original and corrected
                    return -1248.47, -1248.47, True

                # Interpret the bytes in different endian formats
                big_endian = struct.unpack('>f', check_bytes)[0]  # Standard (big-endian)
                little_endian = struct.unpack('<f', check_bytes)[0]  # Reversed (little-endian)
                # Less common mixed-endian formats, useful for specific device quirks
                mixed1_bytes = bytes([check_bytes[2], check_bytes[3], check_bytes[0], check_bytes[1]])
                mixed1 = struct.unpack('>f', mixed1_bytes)[0]  # Mixed format 1
                mixed2_bytes = bytes([check_bytes[1], check_bytes[0], check_bytes[3], check_bytes[2]])
                mixed2 = struct.unpack('>f', mixed2_bytes)[0]  # Mixed format 2

                # Log all interpretations for debugging
                logger.debug(f"IEEE754 interpretations of {binascii.hexlify(check_bytes).decode('ascii')}:")
                logger.debug(f"  Big-endian (>f): {big_endian}")
                logger.debug(f"  Little-endian (<f): {little_endian}")
                logger.debug(f"  Mixed-endian 1 (>f on {binascii.hexlify(mixed1_bytes).decode('ascii')}): {mixed1}")
                logger.debug(f"  Mixed-endian 2 (>f on {binascii.hexlify(mixed2_bytes).decode('ascii')}): {mixed2}")

                # --- Prioritized Logic for Selecting the Correct Value ---

                # CRITICAL CHECK 1: If big-endian is in the typical 'disconnected' range (~ -1248.xx)
                if -1300 < big_endian < -1100:
                    logger.info(f"Found value in typical disconnected sensor range: {big_endian} (using big-endian)")
                    # Return the big-endian value as both original and corrected
                    return big_endian, big_endian, True

                # CRITICAL CHECK 2: Handle cases where little-endian is a tiny positive number (like e-33)
                # but big-endian is negative. This often indicates an endianness issue. Prefer the negative big-endian.
                if abs(little_endian) < 1e-20 and big_endian < 0:
                    logger.info(f"Replacing near-zero positive little-endian ({little_endian}) with negative big-endian value: {big_endian}")
                    # Return the big-endian value as corrected, keep it as original ref
                    return big_endian, big_endian, True

                # CHECK 3: Check for reasonable CO2 values (400-2000 ppm), prioritizing big-endian
                if 400 < big_endian < 2000:
                    logger.info(f"Found reasonable CO2 value: {big_endian} (using big-endian)")
                    # Standard case, return big-endian
                    return big_endian, big_endian, True

                # CHECK 4: If big-endian is negative (but not the specific disconnected range), it might still be a status/error.
                # Prioritize this over other positive interpretations unless they are clearly CO2 values.
                if big_endian < 0:
                    logger.info(f"Using negative big-endian value (potentially status/error): {big_endian}")
                    return big_endian, big_endian, True # Assume big-endian is the intended negative value

                # CHECK 5: Check other interpretations for reasonable CO2 values if big-endian wasn't suitable
                reasonable_alternatives = []
                for val, name in [(little_endian, "little-endian"), (mixed1, "mixed-endian-1"), (mixed2, "mixed-endian-2")]:
                    if 400 <= val <= 2000:
                        reasonable_alternatives.append((val, name))

                if reasonable_alternatives:
                    # If multiple reasonable CO2 values exist in other formats, log a warning but pick the first one found.
                    # This scenario is less likely but possible.
                    val, name = reasonable_alternatives[0]
                    logger.warning(f"Found reasonable CO2 value in alternative format: {val} ({name}). Big-endian was {big_endian}. Using alternative.")
                    # Return the alternative value, but keep original_big_endian for reference
                    return val, big_endian, True

                # CHECK 6: Check other interpretations for negative values if big-endian wasn't negative.
                negative_alternatives = []
                for val, name in [(little_endian, "little-endian"), (mixed1, "mixed-endian-1"), (mixed2, "mixed-endian-2")]:
                    if val < 0:
                        negative_alternatives.append((val, name))

                if negative_alternatives:
                     # Prioritize the alternative negative value if big-endian wasn't negative
                    val, name = negative_alternatives[0] # Pick the first negative alternative found
                    logger.info(f"Using alternative negative value: {val} ({name}). Big-endian was {big_endian}.")
                    # Return the alternative, keep original big-endian
                    return val, big_endian, True

                # CHECK 7: Fallback to any non-tiny positive value, preferring big-endian.
                positive_fallbacks = []
                # Check big-endian first
                if big_endian > 0 and abs(big_endian) > 1e-10:
                    positive_fallbacks.append((big_endian, "big-endian"))
                # Check others
                for val, name in [(little_endian, "little-endian"), (mixed1, "mixed-endian-1"), (mixed2, "mixed-endian-2")]:
                     if val > 0 and abs(val) > 1e-10:
                        positive_fallbacks.append((val, name))

                if positive_fallbacks:
                    val, name = positive_fallbacks[0] # Prefer big-endian if available due to order added
                    logger.info(f"Using fallback positive value: {val} ({name})")
                    # Return the chosen positive value, keep original big-endian
                    return val, big_endian, True

                # FINAL FALLBACK: If no other logic matched, return the big-endian value as is.
                logger.warning(f"No specific logic matched. Falling back to raw big-endian value: {big_endian}")
                return big_endian, big_endian, True # Return big-endian as the last resort

            except struct.error as e:
                # Handle potential errors during unpacking (e.g., if check_bytes is not 4 bytes)
                logger.warning(f"Error unpacking IEEE754 value from bytes {binascii.hexlify(check_bytes).decode('ascii')}: {e}")
            except Exception as e:
                # Catch any other unexpected errors during processing
                logger.error(f"Unexpected error processing IEEE754 bytes {binascii.hexlify(check_bytes).decode('ascii')}: {e}", exc_info=True)

        # If loop completes without returning, no suitable value was found or processed
        logger.error("Failed to find or interpret any IEEE754 value in the provided bytes.")
        # Return indicating failure
        return None, None, False
    
    def send_who_is(self, low_limit: Optional[int] = None, high_limit: Optional[int] = None) -> Dict[int, Dict]:
        """
        Отправляет запрос Who-Is для обнаружения устройств
        
        Args:
            low_limit: Нижняя граница диапазона ID устройств
            high_limit: Верхняя граница диапазона ID устройств
            
        Returns:
            dict: Обнаруженные устройства {device_id: {info}}
        """
        logger.info("Sending Who-Is request")
        
        # Создаем APDU для Who-Is запроса
        # PDU Type: Unconfirmed Request (0x10)
        # PDU Service Choice: Who-Is (8)
        apdu = bytearray([APDU_UNCONFIRMED_REQ | SERVICE_UNCONFIRMED_WHO_IS])
        
        # Добавляем опциональные пределы, если они указаны
        if low_limit is not None and high_limit is not None:
            # Добавляем нижний предел (контекстный тег 0)
            if low_limit < 0x100:
                apdu += bytearray([0x29, low_limit])  # Context tag 0, length 1
            elif low_limit < 0x10000:
                apdu += bytearray([0x2A]) + struct.pack('>H', low_limit)  # Context tag 0, length 2
            else:
                apdu += bytearray([0x2C]) + struct.pack('>L', low_limit)  # Context tag 0, length 4
            
            # Добавляем верхний предел (контекстный тег 1)
            if high_limit < 0x100:
                apdu += bytearray([0x39, high_limit])  # Context tag 1, length 1
            elif high_limit < 0x10000:
                apdu += bytearray([0x3A]) + struct.pack('>H', high_limit)  # Context tag 1, length 2
            else:
                apdu += bytearray([0x3C]) + struct.pack('>L', high_limit)  # Context tag 1, length 4
        
        # Создаем NPDU (максимально простой)
        # Version: 1
        # Control: 0 (нет дополнительных опций)
        npdu = bytearray([0x01, 0x00])
        
        # Создаем BVLC заголовок для броадкаста
        # Type: BACnet/IP (0x81)
        # Function: Original-Broadcast-NPDU (0x0B)
        # Length: суммарная длина всего пакета
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_BROADCAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем весь пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.info(f"Who-Is packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет на широковещательный адрес
        try:
            self.socket.sendto(packet, ('255.255.255.255', self.server_port))
            logger.info(f"Sent Who-Is broadcast to 255.255.255.255:{self.server_port}")
            
            # Также отправляем локальный броадкаст, если задан server_ip
            if self.server_ip:
                # Получаем сетевую маску из server_ip
                # (упрощенно - предполагаем стандартную маску для класса C)
                parts = self.server_ip.split('.')
                broadcast_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                
                self.socket.sendto(packet, (broadcast_ip, self.server_port))
                logger.info(f"Sent Who-Is broadcast to {broadcast_ip}:{self.server_port}")
                
                # Также отправляем прямой запрос на server_ip
                self.socket.sendto(packet, (self.server_ip, self.server_port))
                logger.info(f"Sent Who-Is direct to {self.server_ip}:{self.server_port}")
        except Exception as e:
            logger.error(f"Error sending Who-Is: {e}")
            
        # Ожидаем и обрабатываем ответы
        responses = []
        try:
            # Ждем несколько секунд, чтобы получить ответы
            for i in range(3):  # Три попытки сбора ответов
                more_responses = self.receive_responses(1)  # Ждем 1 секунду между попытками
                if more_responses:
                    if isinstance(more_responses, list):
                        responses.extend(more_responses)
                    else:
                        responses.append(more_responses)
            
            # Обрабатываем полученные ответы
            devices = {}
            for resp in responses:
                if isinstance(resp, dict) and 'type' in resp and resp['type'] == 'i_am':
                    device_id = resp.get('device_id')
                    if device_id:
                        devices[device_id] = resp.get('device_info', {})
                        logger.info(f"Discovered device {device_id} at {resp.get('device_info', {}).get('ip_address')}")
            
            return devices
        except Exception as e:
            logger.error(f"Error processing Who-Is responses: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {}
    
    def read_property(self, device_id: int, object_type: int, object_instance: int, 
                     property_id: int, array_index: Optional[int] = None) -> Optional[Dict]:
        """
        Чтение свойства BACnet объекта с соответствующей маршрутизацией
        
        Args:
            device_id: ID устройства
            object_type: Тип объекта
            object_instance: Экземпляр объекта
            property_id: ID свойства
            array_index: Индекс массива (при чтении элемента массива)
            
        Returns:
            dict: Ответ на запрос или None в случае ошибки
        """
        logger.debug(f"Reading property {property_id} from {object_type}:{object_instance} on device {device_id}")
        
        # Get invoke ID
        invoke_id = self.get_invoke_id()
        
        # Сохраняем информацию о запросе для последующей обработки ответа
        global invoke_id_to_request_map
        invoke_id_to_request_map[invoke_id] = {
            'device_id': device_id,
            'object_type': object_type,
            'object_instance': object_instance,
            'property_id': property_id
        }
        
        # Строим APDU для ReadProperty запроса
        # APDU типа Confirmed Request (0x00)
        # APDU Flags = 0x05 (Max APDU length = 1476 bytes)
        # Invoke ID = переменная
        # Service Choice = readProperty (0x0C)
        apdu = bytearray([APDU_CONFIRMED_REQ, 0x05, invoke_id, SERVICE_CONFIRMED_READ_PROPERTY])
        
        # Добавляем Object Identifier (Context Tag 0)
        # Формат: Context Tag 0 (0x0C) + 4 байта Object ID
        object_id = ((object_type & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
        object_id_bytes = struct.pack('>L', object_id)
        apdu += bytearray([0x0C]) + object_id_bytes
        
        # Добавляем Property Identifier (Context Tag 1)
        # Формат: Context Tag 1 (0x19) + Property ID
        apdu += bytearray([0x19, property_id])
        
        # Добавляем Array Index, если указан (Context Tag 2)
        if array_index is not None:
            apdu += bytearray([0x29, array_index])
        
        # Строим NPDU (Network Protocol Data Unit)
        # NPDU Version = 1
        # NPDU Control = 0x04 (ожидаем ответ)
        npdu = bytearray([0x01, 0x04])
        
        # Строим BVLC заголовок (BACnet Virtual Link Control)
        # Type = BACnet/IP (0x81)
        # Function = Original-Unicast-NPDU (0x0A)
        # Length = Length of the entire packet
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем полный пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.debug(f"Sending ReadProperty packet to {self.server_ip}:{self.server_port}")
        logger.debug(f"  BVLC: {binascii.hexlify(bvlc).decode('ascii')}")
        logger.debug(f"  NPDU: {binascii.hexlify(npdu).decode('ascii')}")
        logger.debug(f"  APDU: {binascii.hexlify(apdu).decode('ascii')}")
        logger.debug(f"  Full packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет
        try:
            self.socket.sendto(packet, (self.server_ip, self.server_port))
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
        
        # Ждем ответ для этого invoke_id
        response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
        
        # Если ответ не получен и разрешен broadcast, пробуем отправить как broadcast
        if not response and self.use_broadcast:
            logger.debug("No response to unicast, trying broadcast...")
            
            # Заменяем BVLC функцию на Original-Broadcast-NPDU (0x0B)
            bvlc_broadcast = bytearray([0x81, BVLC_ORIGINAL_BROADCAST_NPDU]) + struct.pack('>H', bvlc_length)
            packet_broadcast = bvlc_broadcast + npdu + apdu
            
            logger.debug(f"Broadcast packet: {binascii.hexlify(packet_broadcast).decode('ascii')}")
            
            try:
                # Отправляем на широковещательный адрес
                self.socket.sendto(packet_broadcast, ('255.255.255.255', self.server_port))
                
                # И также на конкретный адрес сервера для страховки
                if self.server_ip:
                    self.socket.sendto(packet_broadcast, (self.server_ip, self.server_port))
                    
                logger.debug("Broadcast packet sent")
            except Exception as e:
                logger.error(f"Error sending broadcast packet: {e}")
                return None
                
            # Ждем ответ еще раз
            response = self.receive_responses(timeout=3, expected_invoke_id=invoke_id)
        
        # Логируем результат
        if response:
            logger.debug(f"Received response for invoke_id {invoke_id}: {response}")
        else:
            logger.warning(f"No response received for invoke_id {invoke_id}")
        
        return response
    
    def receive_responses(self, timeout: float = 5, expected_invoke_id: Optional[int] = None) -> Union[Dict, List[Dict], None]:
        """
        Получение и обработка ответов BACnet
        
        Args:
            timeout: Время ожидания ответа в секундах
            expected_invoke_id: ID запроса, ответ на который ожидается
            
        Returns:
            dict или list[dict]: Один или несколько ответов, или None если нет ответов
        """
        logger.debug(f"Waiting for responses (timeout: {timeout}s), expected invoke_id: {expected_invoke_id}")
        
        # Set socket timeout
        self.socket.settimeout(timeout)
        
        responses = []
        start_time = time.time()
        
        try:
            while time.time() - start_time < timeout:
                try:
                    data, addr = self.socket.recvfrom(2048)  # Увеличиваем буфер приема
                    
                    # Логируем полученный пакет
                    logger.debug(f"Received packet from {addr[0]}:{addr[1]}, length: {len(data)}")
                    logger.debug(f"Raw data: {binascii.hexlify(data).decode('ascii')}")
                    
                    # Базовая проверка пакета
                    if len(data) < 6:  # Минимальная длина для BVLC+NPDU
                        logger.warning(f"Packet too small: {len(data)} bytes")
                        continue
                        
                    if data[0] != 0x81:  # Проверка типа BACnet/IP
                        logger.warning(f"Not a BACnet/IP packet, type: {data[0]:02x}")
                        continue
                        
                    # Разбор BVLC
                    bvlc_type = data[0]
                    bvlc_function = data[1]
                    bvlc_length = struct.unpack('>H', data[2:4])[0]
                    
                    logger.debug(f"BVLC: Type={bvlc_type:02x}, Function={bvlc_function:02x}, Length={bvlc_length}")
                    
                    # Проверка длины пакета
                    if bvlc_length != len(data):
                        logger.warning(f"BVLC length mismatch: expected {bvlc_length}, got {len(data)}")
                    
                    # NPDU начинается с 4-го байта
                    npdu_version = data[4]
                    npdu_control = data[5]
                    
                    logger.debug(f"NPDU: Version={npdu_version}, Control={npdu_control:02x}")
                    
                    # Определяем смещение для APDU на основе флагов NPDU
                    apdu_offset = 6  # После Version и Control
                    
                    # Пропускаем DNET/DLEN/DADR если указаны (бит 5 в control)
                    if npdu_control & NPDU_DEST_PRESENT:
                        logger.debug("NPDU includes destination info")
                        if len(data) > apdu_offset + 2:
                            dnet = struct.unpack('>H', data[apdu_offset:apdu_offset+2])[0]
                            apdu_offset += 2
                            if len(data) > apdu_offset:
                                dlen = data[apdu_offset]
                                apdu_offset += 1 + dlen
                                logger.debug(f"DNET={dnet}, DLEN={dlen}")
                                
                    # Пропускаем SNET/SLEN/SADR если указаны (бит 3 в control)
                    if npdu_control & NPDU_SRC_PRESENT:
                        logger.debug("NPDU includes source info")
                        if len(data) > apdu_offset + 2:
                            snet = struct.unpack('>H', data[apdu_offset:apdu_offset+2])[0]
                            apdu_offset += 2
                            if len(data) > apdu_offset:
                                slen = data[apdu_offset]
                                apdu_offset += 1 + slen
                    
                    # Пропускаем Hop Count если указан (бит 5 или бит 3 в control)
                    if npdu_control & (NPDU_DEST_PRESENT | NPDU_SRC_PRESENT):
                        logger.debug("NPDU includes hop count")
                        apdu_offset += 1
                    
                    # Проверяем, что в пакете есть APDU
                    if len(data) <= apdu_offset:
                        logger.warning("No APDU in packet")
                        continue
                        
                    # APDU начинается после NPDU
                    apdu_type = data[apdu_offset] & 0xF0
                    
                    logger.debug(f"APDU: Type={apdu_type:02x}")
                    
                    # Обрабатываем пакет в зависимости от типа APDU
                    response = self.process_packet(data, addr)
                    
                    if response:
                        logger.debug(f"Processed response: {response}")
                        responses.append(response)
                        
                        # Если мы ждем конкретный invoke_id и нашли его, возвращаем сразу
                        if (expected_invoke_id is not None and 
                            'invoke_id' in response and 
                            response['invoke_id'] == expected_invoke_id):
                            logger.debug(f"Found expected invoke_id {expected_invoke_id}")
                            return response
                            
                except socket.timeout:
                    logger.debug("Socket timeout")
                    break
                except Exception as e:
                    logger.error(f"Error receiving response: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
        
        except Exception as e:
            logger.error(f"Error in receive_responses: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
        finally:
            # Reset socket timeout
            self.socket.settimeout(None)
            
        if not responses:
            logger.warning("No responses received")
            return None
            
        return responses if len(responses) > 1 else responses[0]
    
    def process_packet(self, data: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка полученного BACnet пакета
        
        Args:
            data: Байты пакета
            addr: Адрес отправителя (IP, порт)
            
        Returns:
            dict: Обработанный ответ или None если пакет не удалось обработать
        """
        try:
            # Базовая проверка пакета
            if len(data) < 6:  # Минимальная длина для BVLC+NPDU
                logger.warning(f"Packet too small: {len(data)} bytes")
                return None
                
            if data[0] != 0x81:  # Не BACnet/IP пакет
                logger.warning(f"Not a BACnet/IP packet, type: {data[0]:02x}")
                return None
                
            # Базовый разбор BVLC
            bvlc_type = data[0]
            bvlc_function = data[1]
            bvlc_length = struct.unpack('>H', data[2:4])[0]
            
            # NPDU начинается с 4-го байта
            npdu_version = data[4]
            npdu_control = data[5]
            
            # Определяем смещение для APDU на основе флагов NPDU
            apdu_offset = 6  # После Version и Control
            
            # Пропускаем DNET/DLEN/DADR если указаны (бит 5 в control)
            if npdu_control & NPDU_DEST_PRESENT:
                if len(data) > apdu_offset + 2:
                    dnet = struct.unpack('>H', data[apdu_offset:apdu_offset+2])[0]
                    apdu_offset += 2
                    if len(data) > apdu_offset:
                        dlen = data[apdu_offset]
                        apdu_offset += 1 + dlen
            
            # Пропускаем SNET/SLEN/SADR если указаны (бит 3 в control)
            if npdu_control & NPDU_SRC_PRESENT:
                if len(data) > apdu_offset + 2:
                    snet = struct.unpack('>H', data[apdu_offset:apdu_offset+2])[0]
                    apdu_offset += 2
                    if len(data) > apdu_offset:
                        slen = data[apdu_offset]
                        apdu_offset += 1 + slen
            
            # Пропускаем Hop Count если указан (бит 5 или бит 3 в control)
            if npdu_control & (NPDU_DEST_PRESENT | NPDU_SRC_PRESENT):
                apdu_offset += 1
            
            # Проверяем, что в пакете есть APDU
            if len(data) <= apdu_offset:
                logger.warning("No APDU in packet")
                return None
                
            # APDU начинается после NPDU
            apdu = data[apdu_offset:]
            apdu_type = apdu[0] & 0xF0
            
            # Обрабатываем пакет в зависимости от типа APDU
            if apdu_type == APDU_CONFIRMED_RES:
                # Подтвержденный ответ (Confirmed Response)
                return self.process_confirmed_response(apdu, addr)
                
            elif apdu_type == APDU_SIMPLE_ACK:
                # Простое подтверждение (Simple ACK)
                return self.process_simple_ack(apdu, addr)
                
            elif apdu_type == APDU_COMPLEX_ACK:
                # Комплексный ответ (Complex ACK)
                return self.process_complex_ack(apdu, addr)
                
            elif apdu_type == APDU_ERROR:
                # Ответ с ошибкой (Error)
                return self.process_error(apdu, addr)
                
            elif apdu_type == APDU_REJECT:
                # Отказ в обработке запроса (Reject)
                return self.process_reject(apdu, addr)
                
            elif apdu_type == APDU_ABORT:
                # Прерывание обработки (Abort)
                return self.process_abort(apdu, addr)
                
            elif apdu_type == APDU_UNCONFIRMED_REQ:
                # Неподтвержденный запрос (Unconfirmed Request)
                service_choice = apdu[0] & 0x0F
                
                if service_choice == SERVICE_UNCONFIRMED_I_AM:
                    # I-Am ответ на Who-Is
                    return self.process_i_am(apdu, addr)
                    
                elif service_choice == SERVICE_UNCONFIRMED_COV_NOTIFICATION:
                    # Уведомление об изменении значения
                    return self.process_cov_notification(apdu, addr)
                    
                # Другие типы неподтвержденных запросов
                logger.info(f"Received unconfirmed request, service choice: {service_choice}")
                
            else:
                logger.warning(f"Unknown APDU type: {apdu_type:02x}")
                
            return None
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None
            
    def process_confirmed_response(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка подтвержденного ответа
        """
        if len(apdu) < 3:
            logger.warning("Confirmed response too short")
            return None
            
        # Извлекаем Invoke ID и service choice
        invoke_id = apdu[1]
        service_choice = apdu[2]
        
        logger.debug(f"Confirmed response, invoke_id: {invoke_id}, service: {service_choice}")
        logger.debug(f"Raw response data: {binascii.hexlify(apdu).decode('ascii')}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id)
        
        if not request_info:
            logger.warning(f"No request info for invoke_id {invoke_id}")
            return None
            
        # Создаем базовую структуру ответа
        response = {
            'type': 'complex_ack',  # Изменено с 'confirmed_response' на 'complex_ack' для совместимости
            'invoke_id': invoke_id,
            'service_choice': service_choice,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info
        }
        
        # Добавляем специфичные для сервиса данные
        if service_choice == SERVICE_CONFIRMED_READ_PROPERTY:
            # Парсим значение из ReadProperty ответа
            logger.debug(f"Parsing ReadProperty response data: {binascii.hexlify(apdu[3:]).decode('ascii')}")
            
            # Проверяем наличие данных IEEE754 (плавающая точка) в ответе
            value, raw_value, found = self.search_ieee754_values(apdu)
            if found:
                logger.debug(f"Found IEEE754 value: {value}, raw_value: {raw_value}")
                response['value'] = value
                response['original_value'] = raw_value
                response['success'] = True
                return response
            
            # Если не нашли напрямую, пытаемся использовать стандартный парсер
            try:
                self.parse_read_property_ack(apdu[3:], response)
            except Exception as e:
                logger.error(f"Error parsing ReadProperty response: {e}")
                
        return response
        
    def process_simple_ack(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка простого подтверждения (Simple ACK)
        """
        if len(apdu) < 3:
            logger.warning("Simple ACK too short")
            return None
            
        # Извлекаем Invoke ID и service choice
        invoke_id = apdu[1]
        service_choice = apdu[2]
        
        logger.debug(f"Simple ACK, invoke_id: {invoke_id}, service: {service_choice}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id)
        
        if not request_info:
            logger.warning(f"No request info for invoke_id {invoke_id}")
            return None
            
        # Создаем структуру ответа
        response = {
            'type': 'simple_ack',
            'invoke_id': invoke_id,
            'service_choice': service_choice,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info
        }
        
        # Если это ответ на подписку COV, добавляем информацию
        if service_choice == SERVICE_CONFIRMED_SUBSCRIBE_COV:
            response['success'] = True
            response['message'] = "Successfully subscribed to COV notifications"
        
        return response
        
    def process_complex_ack(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка комплексного ответа (Complex ACK)
        """
        if len(apdu) < 3:
            logger.warning("Complex ACK too short")
            return None
            
        # Извлекаем Invoke ID и service choice
        invoke_id = apdu[1]
        service_choice = apdu[2]
        
        logger.debug(f"Complex ACK, invoke_id: {invoke_id}, service: {service_choice}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id, {})
        
        # Создаем базовую структуру ответа
        response = {
            'type': 'complex_ack',
            'invoke_id': invoke_id,
            'service_choice': service_choice,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info
        }
        
        # Обрабатываем специфичные для сервиса данные
        try:
            if service_choice == SERVICE_CONFIRMED_READ_PROPERTY:
                # Ответ на ReadProperty
                self.parse_read_property_ack(apdu[3:], response)
                
            elif service_choice == SERVICE_CONFIRMED_READ_PROP_MULTIPLE:
                # Ответ на ReadPropertyMultiple
                self.parse_read_property_multiple_ack(apdu[3:], response)
                
            elif service_choice == SERVICE_CONFIRMED_PRIVATE_TRANSFER:
                # Ответ на PrivateTransfer (для Automated Logic)
                self.parse_private_transfer_ack(apdu[3:], response)
                
            elif service_choice == SERVICE_CONFIRMED_GET_EVENT_INFORMATION:
                # Ответ на GetEventInformation
                self.parse_get_event_information_ack(apdu[3:], response)
                
        except Exception as e:
            logger.error(f"Error parsing Complex ACK: {e}")
            import traceback
            logger.error(traceback.format_exc())
            response['error'] = str(e)
            
        return response
        
    def process_error(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка ответа с ошибкой (Error)
        """
        if len(apdu) < 3:
            logger.warning("Error response too short")
            return None
            
        # Извлекаем Invoke ID и service choice
        invoke_id = apdu[1]
        service_choice = apdu[2]
        
        logger.debug(f"Error response, invoke_id: {invoke_id}, service: {service_choice}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id)
        
        if not request_info:
            logger.warning(f"No request info for invoke_id {invoke_id}")
        
        # Создаем структуру ответа с ошибкой
        response = {
            'type': 'error',
            'invoke_id': invoke_id,
            'service_choice': service_choice,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info,
            'success': False
        }
        
        # Парсим данные ошибки
        try:
            # Смещение к данным ошибки (после заголовка)
            offset = 3
            
            # Код ошибки может быть контекстным тегом
            if offset < len(apdu):
                # Ожидаем контекстный тег 0 (error-class)
                if (apdu[offset] & 0xF0) == 0x90:  # Контекстный тег 0
                    error_class = apdu[offset] & 0x07  # Взять только нижние 3 бита, если это простой тег
                    offset += 1
                    # Если длина больше 0, берем значение
                    if error_class == 5:  # Длинный тег
                        tag_len = apdu[offset]
                        offset += 1
                        error_class = int.from_bytes(apdu[offset:offset+tag_len], byteorder='big')
                        offset += tag_len
                    
                    # Ожидаем контекстный тег 1 (error-code)
                    if offset < len(apdu) and (apdu[offset] & 0xF0) == 0xA0:  # Контекстный тег 1
                        error_code = apdu[offset] & 0x07  # Взять только нижние 3 бита, если это простой тег
                        offset += 1
                        # Если длина больше 0, берем значение
                        if error_code == 5:  # Длинный тег
                            tag_len = apdu[offset]
                            offset += 1
                            error_code = int.from_bytes(apdu[offset:offset+tag_len], byteorder='big')
                            offset += tag_len
                        
                        # Получаем читаемые имена для кодов ошибок
                        error_class_name = BACNET_ERROR_CLASSES.get(error_class, f"Unknown class ({error_class})")
                        error_code_name = BACNET_ERROR_CODES.get(error_code, f"Unknown code ({error_code})")
                        
                        response['error_class'] = error_class
                        response['error_code'] = error_code
                        response['error_class_name'] = error_class_name
                        response['error_code_name'] = error_code_name
                        response['error_message'] = f"{error_class_name}: {error_code_name}"
                        
                        logger.error(f"BACnet error: {error_class_name} - {error_code_name}")
        except Exception as e:
            logger.error(f"Error parsing error response: {e}")
            response['parse_error'] = str(e)
            
        return response
        
    def process_reject(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка отказа в обработке запроса (Reject)
        """
        if len(apdu) < 3:
            logger.warning("Reject response too short")
            return None
            
        # Извлекаем Invoke ID и причину отказа
        invoke_id = apdu[1]
        reject_reason = apdu[2]
        
        logger.debug(f"Reject, invoke_id: {invoke_id}, reason: {reject_reason}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id)
        
        # Создаем структуру ответа
        response = {
            'type': 'reject',
            'invoke_id': invoke_id,
            'reject_reason': reject_reason,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info,
            'success': False
        }
        
        # Соответствие кодов причин отказа
        reject_reasons = {
            0: "Other",
            1: "Buffer Overflow",
            2: "Inconsistent Parameters",
            3: "Invalid Parameter Data Type",
            4: "Invalid Tag",
            5: "Missing Required Parameter",
            6: "Parameter Out of Range",
            7: "Too Many Arguments",
            8: "Undefined Enumeration",
            9: "Unrecognized Service",
            10: "Proprietary Abort"
        }
        
        response['reject_reason_text'] = reject_reasons.get(reject_reason, f"Unknown ({reject_reason})")
        logger.error(f"BACnet reject: {response['reject_reason_text']}")
        
        return response
        
    def process_abort(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка прерывания обработки (Abort)
        """
        if len(apdu) < 3:
            logger.warning("Abort response too short")
            return None
            
        # Извлекаем Invoke ID и причину прерывания
        invoke_id = apdu[1]
        abort_reason = apdu[2]
        
        logger.debug(f"Abort, invoke_id: {invoke_id}, reason: {abort_reason}")
        
        # Проверяем, есть ли информация о соответствующем запросе
        global invoke_id_to_request_map
        request_info = invoke_id_to_request_map.get(invoke_id)
        
        # Создаем структуру ответа
        response = {
            'type': 'abort',
            'invoke_id': invoke_id,
            'abort_reason': abort_reason,
            'source_address': f"{addr[0]}:{addr[1]}",
            'request_info': request_info,
            'success': False
        }
        
        # Соответствие кодов причин прерывания
        abort_reasons = {
            0: "Other",
            1: "Buffer Overflow",
            2: "Invalid APDU in this State",
            3: "Preempted by Higher Priority Task",
            4: "Segmentation Not Supported",
            5: "Security Error",
            6: "Insufficient Security",
            7: "Window Size Out of Range",
            8: "Application Exceeded Reply Time",
            9: "Out of Resources",
            10: "TSM Timeout",
            11: "APDU Too Long"
        }
        
        response['abort_reason_text'] = abort_reasons.get(abort_reason, f"Unknown ({abort_reason})")
        logger.error(f"BACnet abort: {response['abort_reason_text']}")
        
        return response
        
    def process_i_am(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка I-Am ответа на Who-Is запрос
        """
        if len(apdu) < 2:
            logger.warning("I-Am response too short")
            return None
            
        # Сервис I-Am имеет формат:
        # - Service Choice = I-Am (0)
        # - Object Identifier (BACnetObjectIdentifier)
        # - Max APDU Length Accepted (Unsigned)
        # - Segmentation Supported (Enumerated)
        # - Vendor ID (Unsigned)
        
        # Указатель на текущую позицию в данных
        offset = 1  # Пропускаем байт с кодом сервиса
        
        # Читаем идентификатор объекта (должен быть Application Tag 12)
        if offset >= len(apdu):
            logger.warning("I-Am: No Object Identifier")
            return None
            
        if (apdu[offset] >> 4) != BACNET_APPLICATION_TAG_OBJECT_ID:
            logger.warning(f"I-Am: Expected Object ID tag, got {apdu[offset] >> 4}")
            return None
        
        # Пропускаем тег и считываем 4 байта идентификатора объекта
        offset += 1
        if offset + 4 > len(apdu):
            logger.warning("I-Am: Object Identifier truncated")
            return None
            
        object_id = struct.unpack('>L', apdu[offset:offset+4])[0]
        object_type = (object_id >> 22) & 0x3FF
        object_instance = object_id & 0x3FFFFF
        
        # Проверяем, что это Device объект
        if object_type != OBJECT_DEVICE:
            logger.warning(f"I-Am: Object is not a Device, but {object_type}")
            return None
            
        device_id = object_instance
        offset += 4
        
        # Читаем максимальную длину APDU (должен быть Application Tag 2)
        if offset >= len(apdu):
            logger.warning("I-Am: No Max APDU Length")
            return None
            
        if (apdu[offset] >> 4) != BACNET_APPLICATION_TAG_UNSIGNED:
            logger.warning(f"I-Am: Expected Unsigned tag for Max APDU Length, got {apdu[offset] >> 4}")
            return None
            
        # Определяем длину значения по тегу
        tag_info = apdu[offset]
        tag_len = tag_info & 0x07
        offset += 1
        
        # Читаем значение максимальной длины APDU
        if offset + tag_len > len(apdu):
            logger.warning("I-Am: Max APDU Length truncated")
            return None
            
        if tag_len == 1:
            max_apdu = apdu[offset]
        elif tag_len == 2:
            max_apdu = struct.unpack('>H', apdu[offset:offset+2])[0]
        elif tag_len == 3:
            max_apdu = struct.unpack('>I', bytes([0, apdu[offset], apdu[offset+1], apdu[offset+2]]))[0]
        elif tag_len == 4:
            max_apdu = struct.unpack('>I', apdu[offset:offset+4])[0]
        else:
            logger.warning(f"I-Am: Unexpected tag length for Max APDU: {tag_len}")
            max_apdu = None
            
        offset += tag_len
        
        # Стандартные значения max_apdu
        max_apdu_values = {
            0: 50,
            1: 128,
            2: 206,
            3: 480,
            4: 1024,
            5: 1476,
            6: "Reserved (6)",
            7: "Reserved (7)"
        }
        
        # Преобразуем код в фактический размер
        max_apdu_actual = max_apdu_values.get(max_apdu, max_apdu)
        
        # Читаем поддержку сегментации (должен быть Application Tag 9)
        if offset >= len(apdu):
            logger.warning("I-Am: No Segmentation Supported")
            return None
            
        if (apdu[offset] >> 4) != BACNET_APPLICATION_TAG_ENUMERATED:
            logger.warning(f"I-Am: Expected Enumerated tag for Segmentation, got {apdu[offset] >> 4}")
            return None
            
        # Определяем длину значения по тегу
        tag_info = apdu[offset]
        tag_len = tag_info & 0x07
        offset += 1
        
        # Читаем значение поддержки сегментации
        if offset + tag_len > len(apdu):
            logger.warning("I-Am: Segmentation Supported truncated")
            return None
            
        if tag_len == 1:
            segmentation = apdu[offset]
        else:
            logger.warning(f"I-Am: Unexpected tag length for Segmentation: {tag_len}")
            segmentation = None
            
        offset += tag_len
        
        # Значения кодов сегментации
        segmentation_values = {
            0: "Segmentation Both",
            1: "Segmentation Transmit",
            2: "Segmentation Receive",
            3: "No Segmentation"
        }
        
        segmentation_text = segmentation_values.get(segmentation, f"Unknown ({segmentation})")
        
        # Читаем Vendor ID (должен быть Application Tag 2)
        if offset >= len(apdu):
            logger.warning("I-Am: No Vendor ID")
            return None
            
        if (apdu[offset] >> 4) != BACNET_APPLICATION_TAG_UNSIGNED:
            logger.warning(f"I-Am: Expected Unsigned tag for Vendor ID, got {apdu[offset] >> 4}")
            return None
            
        # Определяем длину значения по тегу
        tag_info = apdu[offset]
        tag_len = tag_info & 0x07
        offset += 1
        
        # Читаем значение Vendor ID
        if offset + tag_len > len(apdu):
            logger.warning("I-Am: Vendor ID truncated")
            return None
            
        if tag_len == 1:
            vendor_id = apdu[offset]
        elif tag_len == 2:
            vendor_id = struct.unpack('>H', apdu[offset:offset+2])[0]
        else:
            logger.warning(f"I-Am: Unexpected tag length for Vendor ID: {tag_len}")
            vendor_id = None
            
        # Известные производители BACnet
        vendors = {
            0: "ASHRAE",
            1: "NIST",
            2: "The Trane Company",
            8: "McQuay International",
            10: "Delta Controls",
            11: "Siemens Building Technologies Ltd.",
            12: "York Controls Group",
            14: "Automated Logic Corporation",
            15: "Cimetrics Technology",
            24: "Carrier Corporation",
            92: "Johnson Controls Inc.",
            99: "ABB",
            118: "Honeywell",
            187: "Schneider Electric",
            230: "Yamatake / Azbil Corporation",
            232: "Carel S.p.A."
        }
        
        vendor_name = vendors.get(vendor_id, f"Unknown ({vendor_id})")
        
        # Формируем ответ
        response = {
            'type': 'i_am',
            'device_id': device_id,
            'device_info': {
                'ip_address': addr[0],
                'port': addr[1],
                'max_apdu': max_apdu_actual,
                'segmentation': segmentation_text,
                'vendor_id': vendor_id,
                'vendor_name': vendor_name
            }
        }
        
        # Добавляем устройство в глобальный список устройств
        global discovered_devices
        discovered_devices[device_id] = response['device_info']
        
        logger.info(f"Discovered device {device_id} ({vendor_name}) at {addr[0]}:{addr[1]}")
        return response
        
    def process_cov_notification(self, apdu: bytes, addr: Tuple[str, int]) -> Optional[Dict]:
        """
        Обработка COV-уведомления
        """
        if len(apdu) < 2:
            logger.warning("COV notification too short")
            return None
            
        try:
            # Указатель на текущую позицию в данных
            offset = 1  # Пропускаем байт с кодом сервиса
            
            # Получаем Process Identifier (должен быть контекстный тег 0)
            if offset >= len(apdu) or (apdu[offset] & 0xF0) != 0x00:
                logger.warning("COV notification: Invalid Process Identifier tag")
                return None
                
            # Читаем Process ID (обычно в нашей реализации это 1)
            tag_len = apdu[offset] & 0x07
            offset += 1
            
            if tag_len == 1:
                process_id = apdu[offset]
                offset += 1
            else:
                logger.warning(f"COV notification: Unexpected Process ID length: {tag_len}")
                return None
            
            # Получаем идентификатор объекта-инициатора (контекстный тег 1)
            if offset >= len(apdu) or (apdu[offset] & 0xF0) != 0x10:
                logger.warning("COV notification: Invalid Initiating Device tag")
                return None
                
            offset += 1  # Пропускаем тег
            
            # Читаем 4 байта идентификатора устройства
            if offset + 4 > len(apdu):
                logger.warning("COV notification: Initiating Device ID truncated")
                return None
                
            initiating_device_id = struct.unpack('>L', apdu[offset:offset+4])[0]
            initiating_device_type = (initiating_device_id >> 22) & 0x3FF
            initiating_device_instance = initiating_device_id & 0x3FFFFF
            
            offset += 4
            
            # Проверяем, что это Device объект
            if initiating_device_type != OBJECT_DEVICE:
                logger.warning(f"COV notification: Initiating object is not a Device, but {initiating_device_type}")
                return None
                
            # Получаем идентификатор объекта-мониторинга (контекстный тег 2)
            if offset >= len(apdu) or (apdu[offset] & 0xF0) != 0x20:
                logger.warning("COV notification: Invalid Monitored Object tag")
                return None
                
            offset += 1  # Пропускаем тег
            
            # Читаем 4 байта идентификатора объекта
            if offset + 4 > len(apdu):
                logger.warning("COV notification: Monitored Object ID truncated")
                return None
                
            monitored_object_id = struct.unpack('>L', apdu[offset:offset+4])[0]
            monitored_object_type = (monitored_object_id >> 22) & 0x3FF
            monitored_object_instance = monitored_object_id & 0x3FFFFF
            
            offset += 4
            
            # Получаем временную метку события (контекстный тег 3)
            if offset < len(apdu) and (apdu[offset] & 0xF0) == 0x30:
                # Пропускаем тег и временную метку, если она есть
                offset += 1
                
                # Если тег с длиной 0, это пустое время
                tag_len = apdu[offset] & 0x07
                if tag_len > 0:
                    offset += tag_len  # Пропускаем временную метку
            
            # Получаем список изменившихся свойств (контекстный тег 4)
            if offset >= len(apdu) or (apdu[offset] & 0xF0) != 0x40:
                logger.warning("COV notification: Invalid List of Values tag")
                return None
                
            offset += 1  # Пропускаем тег
            
            # Список изменившихся свойств
            properties = []
            
            # Парсим список свойств
            # В общем случае это открытие тега 4, затем список свойств (с их открытыми/закрытыми тегами),
            # затем закрытие тега 4
            while offset < len(apdu):
                # Каждое свойство имеет формат: property-id, property-value
                
                # Получаем Property Identifier (контекстный тег 0)
                if (apdu[offset] & 0xF0) != 0x00:
                    # Если не тег 0, возможно это конец списка
                    break
                    
                # Читаем Property ID
                offset += 1
                property_id = apdu[offset]
                offset += 1
                
                # Получаем Property Value (контекстный тег 1)
                if offset >= len(apdu) or (apdu[offset] & 0xF0) != 0x10:
                    logger.warning("COV notification: Invalid Property Value tag")
                    break
                    
                offset += 1  # Пропускаем тег
                
                # Читаем значение свойства
                # Это может быть любой из типов BACnet, поэтому используем общую функцию
                value, value_offset = self.decode_bacnet_value(apdu[offset:])
                if value_offset <= 0:
                    logger.warning("COV notification: Could not decode property value")
                    break
                    
                offset += value_offset
                
                # Преобразуем числовой ID свойства в читаемое имя
                property_name = property_names.get(property_id, f"Unknown ({property_id})")
                
                # Добавляем свойство в список
                properties.append({
                    'id': property_id,
                    'name': property_name,
                    'value': value
                })
            
            # Создаем структуру COV-уведомления
            response = {
                'type': 'cov_notification',
                'process_id': process_id,
                'initiating_device_id': initiating_device_instance,
                'monitored_object_type': monitored_object_type,
                'monitored_object_instance': monitored_object_instance,
                'monitored_object_type_name': object_types.get(monitored_object_type, f"Unknown ({monitored_object_type})"),
                'source_address': f"{addr[0]}:{addr[1]}",
                'properties': properties
            }
            
            # Логируем полученное уведомление
            logger.info(f"Received COV notification from device {initiating_device_instance} " +
                        f"for {response['monitored_object_type_name']} {monitored_object_instance}")
            
            # Если у нас есть обратный вызов для COV-уведомлений, вызываем его
            global cov_callback
            if cov_callback:
                try:
                    cov_callback(response)
                except Exception as e:
                    logger.error(f"Error in COV callback: {e}")
            
            return response
            
        except Exception as e:
            logger.error(f"Error processing COV notification: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None
    
    def decode_bacnet_value(self, data: bytes) -> Tuple[Any, int]:
        """
        Декодирование значения BACnet
        
        Args:
            data: Байты данных, начиная с тега значения
            
        Returns:
            tuple: (значение, смещение)
        """
        if not data:
            return None, 0
            
        # Получаем тип тега (первые 4 бита)
        tag_number = (data[0] >> 4) & 0x0F
        
        # Проверяем, открывающий или закрывающий тег
        is_opening = (data[0] & 0x08) != 0 and (data[0] & 0x07) == 6
        is_closing = (data[0] & 0x08) != 0 and (data[0] & 0x07) == 7
        
        if is_opening:
            # Пропускаем открывающий тег и рекурсивно декодируем вложенное значение
            inner_offset = 1
            value = []
            
            while inner_offset < len(data):
                # Проверяем, не закрывающий ли тег следующий
                if data[inner_offset] == (tag_number | 0x0F):
                    # Закрывающий тег, завершаем чтение вложенных значений
                    inner_offset += 1
                    break
                    
                # Декодируем вложенное значение
                inner_value, value_offset = self.decode_bacnet_value(data[inner_offset:])
                if value_offset <= 0:
                    # Ошибка декодирования
                    return None, 0
                    
                value.append(inner_value)
                inner_offset += value_offset
                
            return value, inner_offset
            
        elif is_closing:
            # Просто пропускаем закрывающий тег
            return None, 1
            
        # Обычный тег - декодируем значение
        
        # Длина значения определяется последними 3 битами тега
        tag_len = data[0] & 0x07
        
        # Смещение к данным значения после тега
        offset = 1
        
        # Для расширенного типа тега (первые 4 бита = 0xF)
        if (data[0] >> 4) == 0x0F:
            tag_number = data[offset]
            offset += 1
            
        # Если длина равна 5, следующий байт содержит реальную длину
        if tag_len == 5:
            tag_len = data[offset]
            offset += 1
            
        # Если длина равна 6 (opening tag) или 7 (closing tag), 
        # это структурные теги, которые мы уже обработали выше
            
        # Проверяем, хватает ли данных
        if offset + tag_len > len(data):
            logger.warning(f"Not enough data for tag length: {tag_len}, have {len(data) - offset}")
            return None, 0
            
        # Декодируем значение в зависимости от типа тега
        value = None
        
        if tag_number == APP_TAG_NULL:
            # Null значение
            value = None
            
        elif tag_number == APP_TAG_BOOLEAN:
            # Boolean - значение закодировано в tag_len
            value = (tag_len > 0)
            
        elif tag_number == APP_TAG_UNSIGNED:
            # Unsigned Integer
            if tag_len == 1:
                value = data[offset]
            elif tag_len == 2:
                value = struct.unpack('>H', data[offset:offset+2])[0]
            elif tag_len == 3:
                value = struct.unpack('>I', bytes([0, data[offset], data[offset+1], data[offset+2]]))[0]
            elif tag_len == 4:
                value = struct.unpack('>I', data[offset:offset+4])[0]
                
        elif tag_number == APP_TAG_SIGNED:
            # Signed Integer
            if tag_len == 1:
                value = struct.unpack('>b', data[offset:offset+1])[0]
            elif tag_len == 2:
                value = struct.unpack('>h', data[offset:offset+2])[0]
            elif tag_len == 3:
                # Для 3 байт нужно расширить до 4 с учетом знака
                value = struct.unpack('>i', bytes([0, data[offset], data[offset+1], data[offset+2]]))[0]
                # Корректируем для отрицательных значений
                if value & 0x800000:
                    value = value - 0x1000000
            elif tag_len == 4:
                value = struct.unpack('>i', data[offset:offset+4])[0]
                
        elif tag_number == APP_TAG_REAL:
            # Real (Float)
            if tag_len == 4:
                # Стандартный IEEE754 float
                value = struct.unpack('>f', data[offset:offset+4])[0]
                
        elif tag_number == APP_TAG_DOUBLE:
            # Double
            if tag_len == 8:
                value = struct.unpack('>d', data[offset:offset+8])[0]
                
        elif tag_number == APP_TAG_OCTET_STRING:
            # Octet String
            value = data[offset:offset+tag_len]
            
        elif tag_number == APP_TAG_CHARACTER_STRING:
            # Character String - первый байт это кодировка
            encoding = data[offset]
            # 0 - ASCII/UTF-8, 1 - Unicode (UCS-2), 2 - ISO 8859-1, 3 - Codepage
            if encoding == 0 and tag_len > 1:
                try:
                    value = data[offset+1:offset+tag_len].decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        value = data[offset+1:offset+tag_len].decode('latin1')
                    except:
                        value = str(data[offset+1:offset+tag_len])
            else:
                value = str(data[offset+1:offset+tag_len])
                
        elif tag_number == APP_TAG_BIT_STRING:
            # Bit String - первый байт это число неиспользуемых бит
            unused_bits = data[offset]
            # Преобразуем в строку бит без неиспользуемых в конце
            bits = ''
            for i in range(1, tag_len):
                bits += format(data[offset+i], '08b')
            if bits and unused_bits > 0:
                bits = bits[:-unused_bits]
            value = bits
            
        elif tag_number == APP_TAG_ENUMERATED:
            # Enumerated - как Unsigned Integer
            if tag_len == 1:
                value = data[offset]
            elif tag_len == 2:
                value = struct.unpack('>H', data[offset:offset+2])[0]
            elif tag_len == 3:
                value = struct.unpack('>I', bytes([0, data[offset], data[offset+1], data[offset+2]]))[0]
            elif tag_len == 4:
                value = struct.unpack('>I', data[offset:offset+4])[0]
                
        elif tag_number == APP_TAG_DATE:
            # Date
            if tag_len == 4:
                year = data[offset] + 1900
                month = data[offset+1]
                day = data[offset+2]
                day_of_week = data[offset+3]
                
                # Специальные значения
                if year == 255:
                    year = 'unspecified'
                if month == 255:
                    month = 'unspecified'
                if day == 255:
                    day = 'unspecified'
                if day_of_week == 255:
                    day_of_week = 'unspecified'
                    
                value = {
                    'year': year,
                    'month': month,
                    'day': day,
                    'day_of_week': day_of_week
                }
                
        elif tag_number == APP_TAG_TIME:
            # Time
            if tag_len == 4:
                hour = data[offset]
                minute = data[offset+1]
                second = data[offset+2]
                hundredth = data[offset+3]
                
                # Специальные значения
                if hour == 255:
                    hour = 'unspecified'
                if minute == 255:
                    minute = 'unspecified'
                if second == 255:
                    second = 'unspecified'
                if hundredth == 255:
                    hundredth = 'unspecified'
                    
                value = {
                    'hour': hour,
                    'minute': minute,
                    'second': second,
                    'hundredth': hundredth
                }
                
        elif tag_number == APP_TAG_OBJECT_ID:
            # Object Identifier
            if tag_len == 4:
                object_id = struct.unpack('>L', data[offset:offset+4])[0]
                object_type = (object_id >> 22) & 0x3FF
                object_instance = object_id & 0x3FFFFF
                
                value = {
                    'type': object_type,
                    'instance': object_instance,
                    'type_name': object_types.get(object_type, f"Unknown ({object_type})")
                }
                
        else:
            # Неизвестный тип тега
            logger.warning(f"Unknown tag number: {tag_number}")
            value = data[offset:offset+tag_len]
            
        # Возвращаем значение и общее смещение
        return value, offset + tag_len
        
    def parse_read_property_ack(self, data: bytes, response: Dict) -> None:
        """
        Разбор ответа на ReadProperty запрос
        
        Args:
            data: Данные ответа (без заголовков)
            response: Словарь для заполнения результатами
        """
        try:
            # Проверяем наличие данных
            if not data:
                logger.warning("No data in ReadProperty ACK")
                response['error'] = "No data in response"
                return
                
            # Указатель на текущую позицию в данных
            offset = 0
            
            # Получаем Object Identifier (должен быть контекстный тег 0)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x00:
                logger.warning("ReadProperty ACK: Invalid Object Identifier tag")
                response['error'] = "Invalid Object Identifier tag"
                return
                
            # Пропускаем тег и считываем 4 байта идентификатора объекта
            offset += 1
            if offset + 4 > len(data):
                logger.warning("ReadProperty ACK: Object Identifier truncated")
                response['error'] = "Object Identifier truncated"
                return
                
            object_id = struct.unpack('>L', data[offset:offset+4])[0]
            object_type = (object_id >> 22) & 0x3FF
            object_instance = object_id & 0x3FFFFF
            
            offset += 4
            
            # Получаем Property Identifier (должен быть контекстный тег 1)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x10:
                logger.warning("ReadProperty ACK: Invalid Property Identifier tag")
                response['error'] = "Invalid Property Identifier tag"
                return
                
            # Пропускаем тег и считываем идентификатор свойства
            offset += 1
            property_id = data[offset]
            offset += 1
            
            # Получаем Array Index (опционально, контекстный тег 2)
            array_index = None
            if offset < len(data) and (data[offset] & 0xF0) == 0x20:
                # Пропускаем тег
                offset += 1
                
                # Считываем индекс массива
                if offset < len(data):
                    array_index = data[offset]
                    offset += 1
            
            # Получаем Property Value (должен быть контекстный тег 3)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x30:
                logger.warning("ReadProperty ACK: Invalid Property Value tag")
                response['error'] = "Invalid Property Value tag"
                return
                
            # Пропускаем тег и считываем значение свойства
            offset += 1
            
            # Декодируем значение
            value, value_offset = self.decode_bacnet_value(data[offset:])
            if value_offset <= 0:
                logger.warning("ReadProperty ACK: Could not decode property value")
                response['error'] = "Could not decode property value"
                return
                
            # Получаем читаемые имена для типа объекта и свойства
            object_type_name = object_types.get(object_type, f"Unknown ({object_type})")
            property_name = property_names.get(property_id, f"Unknown ({property_id})")
            
            # Заполняем ответ
            response['object_type'] = object_type
            response['object_instance'] = object_instance
            response['object_type_name'] = object_type_name
            response['property_id'] = property_id
            response['property_name'] = property_name
            response['array_index'] = array_index
            response['value'] = value
            response['success'] = True
            
            # Обновляем глобальные переменные для работы с клиентом
            # Только для совместимости со старым кодом
            global current_value, current_object_name, current_description
            
            if property_id == PROP_PRESENT_VALUE:
                if isinstance(value, (int, float)):
                    current_value = float(value)
                elif isinstance(value, dict) and 'value' in value:
                    current_value = float(value['value'])
                    
            elif property_id == PROP_OBJECT_NAME:
                current_object_name = value
                
            elif property_id == PROP_DESCRIPTION:
                current_description = value
                
        except Exception as e:
            logger.error(f"Error parsing ReadProperty ACK: {e}")
            import traceback
            logger.error(traceback.format_exc())
            response['error'] = str(e)
            response['success'] = False
    
    def parse_read_property_multiple_ack(self, data: bytes, response: Dict) -> None:
        """
        Разбор ответа на ReadPropertyMultiple запрос
        
        Args:
            data: Данные ответа (без заголовков)
            response: Словарь для заполнения результатами
        """
        try:
            # Проверяем наличие данных
            if not data:
                logger.warning("No data in ReadPropertyMultiple ACK")
                response['error'] = "No data in response"
                return
                
            # Указатель на текущую позицию в данных
            offset = 0
            
            # Ожидаем открывающий тег для списка результатов
            if offset >= len(data) or data[offset] != 0x0E:  # Opening Tag 0
                logger.warning("ReadPropertyMultiple ACK: Invalid opening tag for list of results")
                response['error'] = "Invalid opening tag for list of results"
                return
                
            offset += 1
            
            # Список объектов и их свойств
            objects = []
            
            # Парсим до конца данных или до закрывающего тега
            while offset < len(data) and data[offset] != 0x0F:  # Closing Tag 0
                # Каждый результат имеет формат:
                # 1. Object Identifier
                # 2. List of Results
                
                # Получаем идентификатор объекта (контекстный тег 0)
                if offset >= len(data) or (data[offset] & 0xF0) != 0x00:
                    logger.warning("ReadPropertyMultiple ACK: Invalid Object Identifier tag")
                    break
                    
                # Пропускаем тег и считываем 4 байта идентификатора объекта
                offset += 1
                if offset + 4 > len(data):
                    logger.warning("ReadPropertyMultiple ACK: Object Identifier truncated")
                    break
                    
                object_id = struct.unpack('>L', data[offset:offset+4])[0]
                object_type = (object_id >> 22) & 0x3FF
                object_instance = object_id & 0x3FFFFF
                
                offset += 4
                
                # Получаем читаемое имя для типа объекта
                object_type_name = object_types.get(object_type, f"Unknown ({object_type})")
                
                # Создаем структуру для объекта
                object_info = {
                    'object_type': object_type,
                    'object_instance': object_instance,
                    'object_type_name': object_type_name,
                    'properties': []
                }
                
                # Ожидаем открывающий тег для списка свойств
                if offset >= len(data) or data[offset] != 0x1E:  # Opening Tag 1
                    logger.warning("ReadPropertyMultiple ACK: Invalid opening tag for list of properties")
                    break
                    
                offset += 1
                
                # Парсим свойства до закрывающего тега
                while offset < len(data) and data[offset] != 0x1F:  # Closing Tag 1
                    # Каждое свойство имеет формат:
                    # 1. Property Identifier
                    # 2. Optional Array Index
                    # 3. Property Value
                    
                    # Получаем Property Identifier (контекстный тег 0)
                    if offset >= len(data) or (data[offset] & 0xF0) != 0x00:
                        logger.warning("ReadPropertyMultiple ACK: Invalid Property Identifier tag")
                        break
                        
                    # Пропускаем тег и считываем идентификатор свойства
                    offset += 1
                    if offset >= len(data):
                        logger.warning("ReadPropertyMultiple ACK: Property Identifier truncated")
                        break
                        
                    property_id = data[offset]
                    offset += 1
                    
                    # Получаем читаемое имя для свойства
                    property_name = property_names.get(property_id, f"Unknown ({property_id})")
                    
                    # Проверяем, есть ли Array Index (контекстный тег 1)
                    array_index = None
                    if offset < len(data) and (data[offset] & 0xF0) == 0x10:
                        # Пропускаем тег и считываем индекс массива
                        offset += 1
                        if offset < len(data):
                            array_index = data[offset]
                            offset += 1
                    
                    # Ожидаем открывающий тег для значения свойства (контекстный тег 2)
                    if offset >= len(data) or (data[offset] & 0xF0) != 0x20:
                        logger.warning("ReadPropertyMultiple ACK: Invalid Property Value tag")
                        break
                        
                    # Пропускаем тег
                    offset += 1
                    
                    # Проверяем, есть ли ошибка вместо значения (Application Tag 0 - Error)
                    if offset < len(data) and data[offset] == 0x91:
                        # Ошибка чтения свойства - парсим класс и код ошибки
                        offset += 1
                        
                        # Ожидаем контекстный тег 0 (error-class)
                        if offset >= len(data) or (data[offset] & 0xF0) != 0x00:
                            logger.warning("ReadPropertyMultiple ACK: Invalid error-class tag")
                            break
                            
                        # Пропускаем тег и считываем класс ошибки
                        offset += 1
                        if offset >= len(data):
                            logger.warning("ReadPropertyMultiple ACK: error-class truncated")
                            break
                            
                        error_class = data[offset]
                        offset += 1
                        
                        # Ожидаем контекстный тег 1 (error-code)
                        if offset >= len(data) or (data[offset] & 0xF0) != 0x10:
                            logger.warning("ReadPropertyMultiple ACK: Invalid error-code tag")
                            break
                            
                        # Пропускаем тег и считываем код ошибки
                        offset += 1
                        if offset >= len(data):
                            logger.warning("ReadPropertyMultiple ACK: error-code truncated")
                            break
                            
                        error_code = data[offset]
                        offset += 1
                        
                        # Получаем читаемые имена для ошибки
                        error_class_name = error_classes.get(error_class, f"Unknown class ({error_class})")
                        error_code_name = error_codes.get(error_code, f"Unknown code ({error_code})")
                        
                        # Добавляем информацию об ошибке в свойство
                        property_info = {
                            'property_id': property_id,
                            'property_name': property_name,
                            'array_index': array_index,
                            'error': {
                                'class': error_class,
                                'code': error_code,
                                'class_name': error_class_name,
                                'code_name': error_code_name,
                                'message': f"{error_class_name}: {error_code_name}"
                            }
                        }
                        
                    else:
                        # Нормальное значение - декодируем его
                        value, value_offset = self.decode_bacnet_value(data[offset:])
                        if value_offset <= 0:
                            logger.warning("ReadPropertyMultiple ACK: Could not decode property value")
                            break
                            
                        offset += value_offset
                        
                        # Добавляем информацию о свойстве
                        property_info = {
                            'property_id': property_id,
                            'property_name': property_name,
                            'array_index': array_index,
                            'value': value
                        }
                        
                        # Обновляем глобальные переменные для работы с клиентом
                        # Только для совместимости со старым кодом
                        if object_type == OBJECT_ANALOG_INPUT and property_id == PROP_PRESENT_VALUE:
                            global current_value
                            if isinstance(value, (int, float)):
                                current_value = float(value)
                            elif isinstance(value, dict) and 'value' in value:
                                current_value = float(value['value'])
                                
                        elif property_id == PROP_OBJECT_NAME:
                            global current_object_name
                            current_object_name = value
                            
                        elif property_id == PROP_DESCRIPTION:
                            global current_description
                            current_description = value
                    
                    # Ожидаем закрывающий тег для значения свойства (контекстный тег 2)
                    if offset >= len(data) or (data[offset] & 0xF0) != 0x20:
                        logger.warning("ReadPropertyMultiple ACK: Missing closing tag for property value")
                        break
                        
                    # Пропускаем закрывающий тег
                    offset += 1
                    
                    # Добавляем свойство в список свойств объекта
                    object_info['properties'].append(property_info)
                
                # Пропускаем закрывающий тег для списка свойств (контекстный тег 1)
                if offset < len(data) and data[offset] == 0x1F:
                    offset += 1
                
                # Добавляем объект в список объектов
                objects.append(object_info)
            
            # Пропускаем закрывающий тег для списка результатов (контекстный тег 0)
            if offset < len(data) and data[offset] == 0x0F:
                offset += 1
            
            # Заполняем ответ
            response['objects'] = objects
            response['success'] = True
            
        except Exception as e:
            logger.error(f"Error parsing ReadPropertyMultiple ACK: {e}")
            import traceback
            logger.error(traceback.format_exc())
            response['error'] = str(e)
            response['success'] = False
            
    def read_properties_multiple(self, device_id: int, object_requests: List[Dict]) -> Optional[Dict]:
        """
        Read multiple properties of multiple objects in a single request
        
        Args:
            device_id: Device ID
            object_requests: List of dictionaries with requests:
                             [
                                {
                                    'object_type': object type,
                                    'object_instance': object instance,
                                    'property_ids': [list of property IDs]
                                },
                                ...
                             ]
        
        Returns:
            dict: Response to the request or None in case of error
        """
        logger.info(f"Reading multiple properties from device {device_id}")
        
        
        # Get invoke ID
        invoke_id = self.get_invoke_id()
        
        # Сохраняем информацию о запросе для последующей обработки ответа
        global invoke_id_to_request_map
        invoke_id_to_request_map[invoke_id] = {
            'device_id': device_id,
            'object_requests': object_requests
        }
        
        # Строим APDU для ReadPropertyMultiple запроса
        # APDU типа Confirmed Request (0x00)
        # APDU Flags = 0x05 (Max APDU length = 1476 bytes)
        # Invoke ID = переменная
        # Service Choice = readPropertyMultiple (0x0E)
        apdu = bytearray([APDU_CONFIRMED_REQ, 0x05, invoke_id, SERVICE_CONFIRMED_READ_PROP_MULTIPLE])
        
        # Добавляем список запросов объектов
        apdu += bytearray([0x0E])  # Opening Tag 0 (List of Read Access Specifications)
        
        # Для каждого объекта
        for obj_req in object_requests:
            object_type = obj_req['object_type']
            object_instance = obj_req['object_instance']
            property_ids = obj_req.get('property_ids', [])
            
            # Добавляем идентификатор объекта (контекстный тег 0)
            # Формат: Context Tag 0 (0x0C) + 4 байта Object ID
            object_id = ((object_type & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
            object_id_bytes = struct.pack('>L', object_id)
            apdu += bytearray([0x0C]) + object_id_bytes
            
            # Добавляем список свойств (контекстный тег 1)
            apdu += bytearray([0x1E])  # Opening Tag 1 (Property ID List)
            
            # Для каждого ID свойства
            for property_id in property_ids:
                # Добавляем Property Identifier (контекстный тег 0)
                # Формат: Context Tag 0 (0x09) + Property ID
                apdu += bytearray([0x09, property_id])
                
                # Для массивов можно добавить индекс массива (контекстный тег 1)
                # Но мы пока не реализуем это
            
            apdu += bytearray([0x1F])  # Closing Tag 1 (Property ID List)
        
        apdu += bytearray([0x0F])  # Closing Tag 0 (List of Read Access Specifications)
        
        # Строим NPDU (Network Protocol Data Unit)
        # NPDU Version = 1
        # NPDU Control = 0x04 (ожидаем ответ)
        npdu = bytearray([0x01, 0x04])
        
        # Строим BVLC заголовок (BACnet Virtual Link Control)
        # Type = BACnet/IP (0x81)
        # Function = Original-Unicast-NPDU (0x0A)
        # Length = Length of the entire packet
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем полный пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.debug(f"Sending ReadPropertyMultiple packet to {self.server_ip}:{self.server_port}")
        logger.debug(f"  Full packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет
        try:
            self.socket.sendto(packet, (self.server_ip, self.server_port))
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
        
        # Ждем ответ для этого invoke_id
        response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
        
        # Если ответ не получен и разрешен broadcast, пробуем отправить как broadcast
        if not response and self.use_broadcast:
            logger.debug("No response to unicast, trying broadcast...")
            
            # Заменяем BVLC функцию на Original-Broadcast-NPDU (0x0B)
            bvlc_broadcast = bytearray([0x81, BVLC_ORIGINAL_BROADCAST_NPDU]) + struct.pack('>H', bvlc_length)
            packet_broadcast = bvlc_broadcast + npdu + apdu
            
            try:
                # Отправляем на широковещательный адрес
                self.socket.sendto(packet_broadcast, ('255.255.255.255', self.server_port))
                
                # И также на конкретный адрес сервера для страховки
                if self.server_ip:
                    self.socket.sendto(packet_broadcast, (self.server_ip, self.server_port))
                    
                logger.debug("Broadcast packet sent")
            except Exception as e:
                logger.error(f"Error sending broadcast packet: {e}")
                return None
                
            # Ждем ответ еще раз
            response = self.receive_responses(timeout=3, expected_invoke_id=invoke_id)
        
        # Логируем результат
        if response:
            logger.debug(f"Received response for invoke_id {invoke_id}: {response}")
        else:
            logger.warning(f"No response received for invoke_id {invoke_id}")
        
        return response
    
    def read_properties(self, device_id: int, object_type: int, object_instance: int, property_ids: List[int]) -> Dict:
        """
        Чтение нескольких свойств одного объекта за один запрос
        
        Args:
            device_id: ID устройства
            object_type: Тип объекта
            object_instance: Экземпляр объекта
            property_ids: Список ID свойств для чтения
            
        Returns:
            dict: Словарь со свойствами и их значениями
        """
        logger.info(f"Reading properties {property_ids} from {object_type}:{object_instance} on device {device_id}")
        
        result = {}
        
        # Пытаемся использовать ReadPropertyMultiple, если поддерживается
        if self.support_read_property_multiple:
            try:
                # Формируем запрос для ReadPropertyMultiple
                object_requests = [{
                    'object_type': object_type,
                    'object_instance': object_instance,
                    'property_ids': property_ids
                }]
                
                # Get invoke ID
                invoke_id = self.get_invoke_id()
                
                # Сохраняем информацию о запросе
                global invoke_id_to_request_map
                invoke_id_to_request_map[invoke_id] = {
                    'device_id': device_id,
                    'object_requests': object_requests
                }
                
                # Строим APDU для ReadPropertyMultiple запроса
                apdu = bytearray([
                    APDU_CONFIRMED_REQ,      # PDU Type = Confirmed Request
                    0x05,                     # Max APDU length = 1476 bytes
                    invoke_id,                # Invoke ID
                    SERVICE_CONFIRMED_READ_PROP_MULTIPLE  # Service Choice
                ])
                
                # Добавляем список запросов объектов
                apdu += bytearray([0x0E])  # Opening Tag 0 (List of Read Access Specifications)
                
                # Добавляем идентификатор объекта (контекстный тег 0)
                object_id = ((object_type & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
                object_id_bytes = struct.pack('>L', object_id)
                apdu += bytearray([0x0C]) + object_id_bytes
                
                # Добавляем список свойств (контекстный тег 1)
                apdu += bytearray([0x1E])  # Opening Tag 1 (Property ID List)
                
                # Для каждого ID свойства
                for property_id in property_ids:
                    # Добавляем Property Identifier (контекстный тег 0)
                    apdu += bytearray([0x09, property_id])
                
                apdu += bytearray([0x1F])  # Closing Tag 1 (Property ID List)
                apdu += bytearray([0x0F])  # Closing Tag 0 (List of Read Access Specifications)
                
                # Строим NPDU
                npdu = bytearray([0x01, 0x04])  # Version = 1, Control = 0x04 (ожидаем ответ)
                
                # Строим BVLC заголовок
                bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
                bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
                
                # Собираем полный пакет
                packet = bvlc + npdu + apdu
                
                # Логируем пакет
                logger.debug(f"Sending ReadPropertyMultiple packet: {binascii.hexlify(packet).decode('ascii')}")
                
                # Отправляем пакет
                self.socket.sendto(packet, (self.server_ip, self.server_port))
                
                # Ждем ответ
                response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
                
                # Если получили ответ
                if response and response.get('success'):
                    # Обрабатываем результаты
                    for obj in response.get('objects', []):
                        # Проверяем, что это нужный нам объект
                        if obj['object_type'] == object_type and obj['object_instance'] == object_instance:
                            # Обрабатываем свойства
                            for prop in obj.get('properties', []):
                                # Добавляем свойство в результат
                                property_id = prop['property_id']
                                # Пропускаем свойства с ошибками
                                if 'error' not in prop:
                                    result[property_id] = prop['value']
                                    # Добавляем читаемое имя свойства
                                    result[f"{property_id}_name"] = prop['property_name']
                            
                    # Если свойства успешно прочитаны, возвращаем результат
                    if result:
                        return {'success': True, 'properties': result}
                
                # Если ReadPropertyMultiple не удался, запоминаем это и используем ReadProperty
                logger.warning("ReadPropertyMultiple failed, using ReadProperty instead")
                self.support_read_property_multiple = False
                
            except Exception as e:
                logger.error(f"Error in ReadPropertyMultiple: {e}")
                # Отключаем поддержку ReadPropertyMultiple при ошибке
                self.support_read_property_multiple = False
        
        # Используем обычный ReadProperty для каждого свойства
        logger.info("Using individual ReadProperty requests")
        
        for property_id in property_ids:
            # Читаем свойство
            response = self.read_property(device_id, object_type, object_instance, property_id)
            
            # Если успешно, добавляем в результат
            if response and response.get('success'):
                result[property_id] = response['value']
                result[f"{property_id}_name"] = response['property_name']
        
        return {'success': len(result) > 0, 'properties': result}
    
    def subscribe_cov(self, device_id: int, object_type: int, object_instance: int, 
                     lifetime: int = 0, confirmed: bool = True, process_id: int = 1,
                     issue_confirmed_notifications: bool = True) -> Optional[Dict]:
        """
        Подписка на уведомления об изменении значения (COV)
        
        Args:
            device_id: ID устройства
            object_type: Тип объекта
            object_instance: Экземпляр объекта
            lifetime: Время жизни подписки в секундах (0 = бессрочно)
            confirmed: Запрашивать ли подтверждение подписки
            process_id: ID процесса для идентификации подписки
            issue_confirmed_notifications: Запрашивать ли подтверждение COV-уведомлений
            
        Returns:
            dict: Результат подписки или None в случае ошибки
        """
        logger.info(f"Subscribing to COV for {object_type}:{object_instance} on device {device_id}")
        
        # Get invoke ID
        invoke_id = self.get_invoke_id()
        
        # Сохраняем информацию о запросе для последующей обработки ответа
        global invoke_id_to_request_map
        invoke_id_to_request_map[invoke_id] = {
            'device_id': device_id,
            'object_type': object_type,
            'object_instance': object_instance,
            'process_id': process_id,
            'subscribe_type': 'cov'
        }
        
        # Строим APDU для SubscribeCOV запроса
        # APDU типа Confirmed Request (0x00)
        # APDU Flags = 0x05 (Max APDU length = 1476 bytes)
        # Invoke ID = переменная
        # Service Choice = subscribeCOV (0x05)
        apdu = bytearray([APDU_CONFIRMED_REQ, 0x05, invoke_id, SERVICE_CONFIRMED_SUBSCRIBE_COV])
        
        # Добавляем Subscriber Process Identifier (контекстный тег 0)
        # Формат: Context Tag 0 (0x09) + Process ID
        apdu += bytearray([0x09, process_id])
        
        # Добавляем Object Identifier (контекстный тег 1)
        # Формат: Context Tag 1 (0x1C) + 4 байта Object ID
        object_id = ((object_type & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
        object_id_bytes = struct.pack('>L', object_id)
        apdu += bytearray([0x1C]) + object_id_bytes
        
        # Добавляем Issue Confirmed Notifications (контекстный тег 2)
        # Формат: Context Tag 2 (0x29) + Значение (0/1)
        apdu += bytearray([0x29, 1 if issue_confirmed_notifications else 0])
        
        # Добавляем Lifetime (контекстный тег 3)
        # Формат: Context Tag 3 (0x39) + Lifetime
        apdu += bytearray([0x39, lifetime])
        
        # Строим NPDU (Network Protocol Data Unit)
        # NPDU Version = 1
        # NPDU Control = 0x04 (ожидаем ответ)
        npdu = bytearray([0x01, 0x04])
        
        # Строим BVLC заголовок (BACnet Virtual Link Control)
        # Type = BACnet/IP (0x81)
        # Function = Original-Unicast-NPDU (0x0A)
        # Length = Length of the entire packet
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем полный пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.info(f"Sending SubscribeCOV packet to {self.server_ip}:{self.server_port}")
        logger.debug(f"  Full packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет
        try:
            self.socket.sendto(packet, (self.server_ip, self.server_port))
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
        
        # Ждем ответ для этого invoke_id
        response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
        
        # Логируем результат
        if response:
            if response.get('type') == 'simple_ack':
                logger.info(f"Successfully subscribed to COV for {object_type}:{object_instance}")
                
                # Регистрируем подписку в глобальном списке
                global cov_subscriptions
                sub_key = f"{device_id}:{object_type}:{object_instance}"
                cov_subscriptions[sub_key] = {
                    'device_id': device_id,
                    'object_type': object_type,
                    'object_instance': object_instance,
                    'process_id': process_id,
                    'lifetime': lifetime,
                    'issue_confirmed_notifications': issue_confirmed_notifications,
                    'timestamp': time.time()
                }
                
                # Возвращаем успех и информацию о подписке
                return {
                    'success': True,
                    'subscription': cov_subscriptions[sub_key],
                    'message': f"Successfully subscribed to COV for {object_type}:{object_instance}"
                }
            else:
                logger.warning(f"Failed to subscribe to COV: {response}")
                return {
                    'success': False,
                    'error': response.get('error', 'Unknown error'),
                    'message': f"Failed to subscribe to COV for {object_type}:{object_instance}"
                }
        else:
            logger.warning(f"No response received for SubscribeCOV request")
            return {
                'success': False,
                'error': 'No response',
                'message': f"No response from device {device_id}"
            }
            
    def unsubscribe_cov(self, device_id: int, object_type: int, object_instance: int, process_id: int = 1) -> Optional[Dict]:
        """
        Отмена подписки на уведомления об изменении значения (COV)
        
        Args:
            device_id: ID устройства
            object_type: Тип объекта
            object_instance: Экземпляр объекта
            process_id: ID процесса для идентификации подписки
            
        Returns:
            dict: Результат отмены подписки или None в случае ошибки
        """
        logger.info(f"Unsubscribing from COV for {object_type}:{object_instance} on device {device_id}")
        
        # Get invoke ID
        invoke_id = self.get_invoke_id()
        
        # Сохраняем информацию о запросе для последующей обработки ответа
        global invoke_id_to_request_map
        invoke_id_to_request_map[invoke_id] = {
            'device_id': device_id,
            'object_type': object_type,
            'object_instance': object_instance,
            'process_id': process_id,
            'subscribe_type': 'unsubscribe_cov'
        }
        
        # Строим APDU для SubscribeCOV запроса (отмена - без lifetime и confirmed)
        # APDU типа Confirmed Request (0x00)
        # APDU Flags = 0x05 (Max APDU length = 1476 bytes)
        # Invoke ID = переменная
        # Service Choice = subscribeCOV (0x05)
        apdu = bytearray([APDU_CONFIRMED_REQ, 0x05, invoke_id, SERVICE_CONFIRMED_SUBSCRIBE_COV])
        
        # Добавляем Subscriber Process Identifier (контекстный тег 0)
        # Формат: Context Tag 0 (0x09) + Process ID
        apdu += bytearray([0x09, process_id])
        
        # Добавляем Object Identifier (контекстный тег 1)
        # Формат: Context Tag 1 (0x1C) + 4 байта Object ID
        object_id = ((object_type & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
        object_id_bytes = struct.pack('>L', object_id)
        apdu += bytearray([0x1C]) + object_id_bytes
        
        # Для отмены подписки не добавляем Issue Confirmed Notifications и Lifetime
        
        # Строим NPDU (Network Protocol Data Unit)
        # NPDU Version = 1
        # NPDU Control = 0x04 (ожидаем ответ)
        npdu = bytearray([0x01, 0x04])
        
        # Строим BVLC заголовок (BACnet Virtual Link Control)
        # Type = BACnet/IP (0x81)
        # Function = Original-Unicast-NPDU (0x0A)
        # Length = Length of the entire packet
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем полный пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.info(f"Sending UnsubscribeCOV packet to {self.server_ip}:{self.server_port}")
        logger.debug(f"  Full packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет
        try:
            self.socket.sendto(packet, (self.server_ip, self.server_port))
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
        
        # Ждем ответ для этого invoke_id
        response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
        
        # Логируем результат
        if response:
            if response.get('type') == 'simple_ack':
                logger.info(f"Successfully unsubscribed from COV for {object_type}:{object_instance}")
                
                # Удаляем подписку из глобального списка
                global cov_subscriptions
                sub_key = f"{device_id}:{object_type}:{object_instance}"
                if sub_key in cov_subscriptions:
                    del cov_subscriptions[sub_key]
                
                # Возвращаем успех
                return {
                    'success': True,
                    'message': f"Successfully unsubscribed from COV for {object_type}:{object_instance}"
                }
            else:
                logger.warning(f"Failed to unsubscribe from COV: {response}")
                return {
                    'success': False,
                    'error': response.get('error', 'Unknown error'),
                    'message': f"Failed to unsubscribe from COV for {object_type}:{object_instance}"
                }
        else:
            logger.warning(f"No response received for UnsubscribeCOV request")
            return {
                'success': False,
                'error': 'No response',
                'message': f"No response from device {device_id}"
            }
            
    def connect_bacnet_sc(self, hub_uri: str, certificate_file: str = None, private_key_file: str = None, 
                        ca_file: str = None, websocket_timeout: int = 30) -> bool:
        """
        Подключение к BACnet/SC хабу через WebSocket с поддержкой TLS
        
        Args:
            hub_uri: URI хаба BACnet/SC (например, 'wss://hub.example.com:47808')
            certificate_file: Путь к клиентскому сертификату для аутентификации
            private_key_file: Путь к приватному ключу для аутентификации
            ca_file: Путь к файлу CA сертификатов для проверки сервера
            websocket_timeout: Таймаут для WebSocket соединения в секундах
            
        Returns:
            bool: True если соединение установлено успешно, иначе False
        """
        # Проверяем, доступны ли необходимые модули
        try:
            import websockets
            import ssl
            import asyncio
        except ImportError as e:
            logger.error(f"BACnet/SC requires websockets, ssl, and asyncio modules: {e}")
            return False
            
        logger.info(f"Connecting to BACnet/SC hub at {hub_uri}")
        
        # Настраиваем SSL контекст, если нужна защита соединения
        ssl_context = None
        if hub_uri.startswith('wss://'):
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Загружаем CA сертификаты для проверки сервера
            if ca_file:
                try:
                    ssl_context.load_verify_locations(ca_file)
                    logger.info(f"Loaded CA certificates from {ca_file}")
                except Exception as e:
                    logger.error(f"Error loading CA certificates: {e}")
                    return False
            
            # Загружаем клиентский сертификат и ключ, если нужна взаимная аутентификация
            if certificate_file and private_key_file:
                try:
                    ssl_context.load_cert_chain(certificate_file, private_key_file)
                    logger.info(f"Loaded client certificate from {certificate_file}")
                except Exception as e:
                    logger.error(f"Error loading client certificate: {e}")
                    return False
                    
            # Настраиваем параметры проверки
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            
        # Сохраняем информацию о соединении BACnet/SC
        self.bacnet_sc_enabled = True
        self.bacnet_sc_hub_uri = hub_uri
        self.bacnet_sc_ssl_context = ssl_context
        self.bacnet_sc_websocket = None
        self.bacnet_sc_timeout = websocket_timeout
        
        # Инициализируем очередь сообщений
        self.bacnet_sc_message_queue = asyncio.Queue()
        
        # Запускаем асинхронный обработчик соединения
        async def connect_and_process():
            try:
                logger.info(f"Connecting to BACnet/SC hub: {hub_uri}")
                async with websockets.connect(
                    hub_uri, 
                    ssl=ssl_context,
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5
                ) as websocket:
                    self.bacnet_sc_websocket = websocket
                    logger.info(f"Connected to BACnet/SC hub: {hub_uri}")
                    
                    # Регистрируем устройство в сети BACnet/SC
                    await self.bacnet_sc_register_device(websocket)
                    
                    # Запускаем задачи для обработки входящих и исходящих сообщений
                    receive_task = asyncio.create_task(self.bacnet_sc_receive_messages(websocket))
                    send_task = asyncio.create_task(self.bacnet_sc_send_messages(websocket))
                    
                    # Ожидаем завершения любой из задач
                    done, pending = await asyncio.wait(
                        [receive_task, send_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    # Отменяем все оставшиеся задачи
                    for task in pending:
                        task.cancel()
                    
                    # Проверяем наличие исключений
                    for task in done:
                        try:
                            task.result()
                        except Exception as e:
                            logger.error(f"Task error: {e}")
                    
                    logger.info("BACnet/SC connection closed")
                    
            except Exception as e:
                logger.error(f"BACnet/SC connection error: {e}")
                self.bacnet_sc_enabled = False
                self.bacnet_sc_websocket = None
                return False
                
        # Создаем и запускаем новый цикл событий для WebSocket соединения
        self.bacnet_sc_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.bacnet_sc_loop)
        
        # Запускаем задачу подключения в отдельном потоке
        self.bacnet_sc_thread = threading.Thread(
            target=lambda: self.bacnet_sc_loop.run_until_complete(connect_and_process()),
            daemon=True
        )
        self.bacnet_sc_thread.start()
        
        # Даем небольшую задержку для установки соединения
        time.sleep(2)
        
        return self.bacnet_sc_enabled and self.bacnet_sc_websocket is not None
        
    async def bacnet_sc_register_device(self, websocket):
        """
        Регистрация устройства в сети BACnet/SC
        
        Args:
            websocket: Активное WebSocket соединение
        """
        try:
            # Формируем пакет регистрации устройства
            device_id = self.device_id if hasattr(self, 'device_id') and self.device_id else 1
            
            # Формируем BVLC заголовок для BACnet/SC
            # BVLC Type: BACnet/SC (0x82)
            # BVLC Function: Register-Foreign-Device (0x05)
            bvlc = bytearray([0x82, 0x05])
            
            # Добавляем информацию о устройстве (SNET, SADR, TTL)
            # Время жизни регистрации в секундах (TTL), например 600 секунд (10 минут)
            ttl = 600
            bvlc += struct.pack('>H', ttl)
            
            # Идентификатор устройства (VMAC)
            vmac = bytearray.fromhex(f"{device_id:08x}")
            bvlc += struct.pack('B', len(vmac)) + vmac
            
            # Отправляем пакет регистрации
            logger.debug(f"Sending BACnet/SC device registration: {binascii.hexlify(bvlc).decode('ascii')}")
            await websocket.send(bvlc)
            
            # Ожидаем ответ на регистрацию
            response = await websocket.recv()
            if len(response) >= 2:
                if response[0] == 0x82:  # BACnet/SC
                    if response[1] == 0x00:  # Result
                        result_code = response[2] if len(response) > 2 else 0
                        if result_code == 0x00:  # Success
                            logger.info("Successfully registered with BACnet/SC hub")
                            return True
                        else:
                            logger.error(f"BACnet/SC registration failed, result code: {result_code}")
                    else:
                        logger.error(f"Unexpected BACnet/SC response function: {response[1]}")
                else:
                    logger.error(f"Unexpected response type: {response[0]}")
            else:
                logger.error("BACnet/SC registration response too short")
                
            return False
            
        except Exception as e:
            logger.error(f"Error in BACnet/SC device registration: {e}")
            return False
            
    async def bacnet_sc_receive_messages(self, websocket):
        """
        Обработка входящих сообщений BACnet/SC
        
        Args:
            websocket: Активное WebSocket соединение
        """
        try:
            while True:
                # Ожидаем сообщение
                message = await websocket.recv()
                
                # Обрабатываем полученное сообщение
                if len(message) >= 2:
                    # Проверяем тип сообщения (BACnet/SC)
                    if message[0] == 0x82:
                        # Определяем функцию BVLC
                        bvlc_function = message[1]
                        
                        if bvlc_function == 0x0A:  # Original-Unicast-NPDU
                            # Извлекаем NPDU из сообщения (начиная с байта 4)
                            npdu_data = message[4:]
                            
                            # Обрабатываем NPDU как обычное BACnet сообщение
                            # Создаем фиктивный адрес для совместимости с остальным кодом
                            addr = (self.bacnet_sc_hub_uri, 0)
                            
                            # Логируем полученное сообщение
                            logger.debug(f"Received BACnet/SC message: {binascii.hexlify(message).decode('ascii')}")
                            
                            # Обрабатываем сообщение стандартным обработчиком
                            try:
                                # Создаем новый пакет с BVLC заголовком для BACnet/IP
                                # для совместимости с имеющимся кодом обработки
                                bvlc_length = len(npdu_data) + 4
                                bvlc_ip = bytearray([0x81, 0x0A]) + struct.pack('>H', bvlc_length)
                                packet = bvlc_ip + npdu_data
                                
                                # Обрабатываем пакет
                                response = self.process_packet(packet, addr)
                                if response:
                                    logger.debug(f"Processed BACnet/SC message: {response}")
                            except Exception as e:
                                logger.error(f"Error processing BACnet/SC message: {e}")
                                
                        elif bvlc_function == 0x0B:  # Original-Broadcast-NPDU
                            # Аналогично обрабатываем широковещательное сообщение
                            npdu_data = message[4:]
                            addr = (self.bacnet_sc_hub_uri, 0)
                            
                            logger.debug(f"Received BACnet/SC broadcast: {binascii.hexlify(message).decode('ascii')}")
                            
                            try:
                                bvlc_length = len(npdu_data) + 4
                                bvlc_ip = bytearray([0x81, 0x0B]) + struct.pack('>H', bvlc_length)
                                packet = bvlc_ip + npdu_data
                                
                                response = self.process_packet(packet, addr)
                                if response:
                                    logger.debug(f"Processed BACnet/SC broadcast: {response}")
                            except Exception as e:
                                logger.error(f"Error processing BACnet/SC broadcast: {e}")
                                
                        elif bvlc_function == 0x00:  # Result
                            # Обрабатываем результат операции
                            result_code = message[2] if len(message) > 2 else 0
                            logger.debug(f"Received BACnet/SC result: {result_code}")
                            
                        else:
                            logger.warning(f"Unsupported BACnet/SC function: {bvlc_function}")
                    else:
                        logger.warning(f"Received non-BACnet/SC message type: {message[0]}")
                else:
                    logger.warning("Received invalid BACnet/SC message (too short)")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info("BACnet/SC connection closed")
        except Exception as e:
            logger.error(f"Error in BACnet/SC message receiver: {e}")
            
    async def bacnet_sc_send_messages(self, websocket):
        """
        Отправка исходящих сообщений BACnet/SC
        
        Args:
            websocket: Активное WebSocket соединение
        """
        try:
            while True:
                # Ожидаем сообщение для отправки из очереди
                message = await self.bacnet_sc_message_queue.get()
                
                # Отправляем сообщение
                await websocket.send(message)
                
                # Помечаем задачу как выполненную
                self.bacnet_sc_message_queue.task_done()
                
        except websockets.exceptions.ConnectionClosed:
            logger.info("BACnet/SC connection closed")
        except Exception as e:
            logger.error(f"Error in BACnet/SC message sender: {e}")
            
    def send_bacnet_sc_message(self, npdu: bytes, is_broadcast: bool = False):
        """
        Отправка BACnet сообщения через BACnet/SC
        
        Args:
            npdu: NPDU данные для отправки
            is_broadcast: Отправлять как широковещательное сообщение
            
        Returns:
            bool: True если сообщение поставлено в очередь, иначе False
        """
        if not self.bacnet_sc_enabled or self.bacnet_sc_websocket is None:
            logger.error("BACnet/SC not enabled or not connected")
            return False
            
        try:
            # Формируем BVLC заголовок для BACnet/SC
            # BVLC Type: BACnet/SC (0x82)
            # BVLC Function: Original-Unicast-NPDU или Original-Broadcast-NPDU
            function = 0x0B if is_broadcast else 0x0A
            bvlc = bytearray([0x82, function])
            
            # Добавляем длину NPDU
            bvlc += struct.pack('>H', len(npdu))
            
            # Собираем полный пакет
            packet = bvlc + npdu
            
            # Логируем отправляемое сообщение
            logger.debug(f"Sending BACnet/SC message: {binascii.hexlify(packet).decode('ascii')}")
            
            # Помещаем сообщение в очередь для отправки
            asyncio.run_coroutine_threadsafe(
                self.bacnet_sc_message_queue.put(packet),
                self.bacnet_sc_loop
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending BACnet/SC message: {e}")
            return False
        
    def read_trend_log(self, device_id: int, object_instance: int, 
                       start_time: Optional[datetime] = None, 
                       stop_time: Optional[datetime] = None,
                       count: int = 0) -> Optional[Dict]:
        """
        Чтение данных из TrendLog объекта
        
        Args:
            device_id: ID устройства
            object_instance: Экземпляр TrendLog объекта
            start_time: Начальное время (если None, используется самая ранняя запись)
            stop_time: Конечное время (если None, используется самая последняя запись)
            count: Максимальное количество записей (0 = без ограничения)
            
        Returns:
            dict: Результат чтения TrendLog или None в случае ошибки
        """
        logger.info(f"Reading TrendLog {object_instance} from device {device_id}")
        
        # Сначала получаем информацию о самом TrendLog объекте
        trend_info = self.read_property(device_id, OBJECT_TREND_LOG, object_instance, PROP_RECORD_COUNT)
        if not trend_info or not trend_info.get('success'):
            logger.error(f"Failed to read TrendLog info: {trend_info}")
            return None
             
        record_count = trend_info.get('value', 0)
        if record_count == 0:
            logger.info("TrendLog is empty")
            return {'success': True, 'records': []}
             
        # Ограничиваем количество записей
        if count > record_count:
            count = record_count
        
        # Get invoke ID
        invoke_id = self.get_invoke_id()
        
        # Сохраняем информацию о запросе для последующей обработки ответа
        global invoke_id_to_request_map
        invoke_id_to_request_map[invoke_id] = {
            'device_id': device_id,
            'object_type': OBJECT_TREND_LOG,
            'object_instance': object_instance
        }
        
        # Строим APDU для ReadRange запроса
        # APDU типа Confirmed Request (0x00)
        # APDU Flags = 0x05 (Max APDU length = 1476 bytes)
        # Invoke ID = переменная
        # Service Choice = readRange (0x26)
        apdu = bytearray([APDU_CONFIRMED_REQ, 0x05, invoke_id, SERVICE_CONFIRMED_READ_RANGE])
        
        # Добавляем Object Identifier (контекстный тег 0)
        # Формат: Context Tag 0 (0x0C) + 4 байта Object ID
        object_id = ((OBJECT_TREND_LOG & 0x3FF) << 22) | (object_instance & 0x3FFFFF)
        object_id_bytes = struct.pack('>L', object_id)
        apdu += bytearray([0x0C]) + object_id_bytes
        
        # Добавляем Property Identifier (контекстный тег 1)
        # Формат: Context Tag 1 (0x19) + Property ID для Log_Buffer
        apdu += bytearray([0x19, PROP_LOG_BUFFER])
        
        # Тип диапазона (контекстный тег 3) - By Time или By Position или All
        if start_time is not None and stop_time is not None:
            # Чтение по времени (контекстный тег 3)
            apdu += bytearray([0x39, 4])  # By Time
            
            # Начальное время (контекстный тег 4)
            apdu += bytearray([0x4E])  # Opening Tag 4 (Time Range)
            
            # Формируем BACnetDateTime для начального времени
            # Сначала дата
            apdu += bytearray([0x73])  # Tag 7 (Date) = Application Tag 3 (Date)
            apdu += bytearray([
                start_time.year - 1900,  # Год (от 1900)
                start_time.month,         # Месяц
                start_time.day,           # День
                start_time.weekday() + 1  # День недели (1 = Понедельник)
            ])
            
            # Затем время
            apdu += bytearray([0x74])  # Tag 7 (Time) = Application Tag 4 (Time)
            apdu += bytearray([
                start_time.hour,          # Час
                start_time.minute,        # Минута
                start_time.second,        # Секунда
                int(start_time.microsecond / 10000)  # Сотые доли секунды
            ])
            
            # Конечное время
            # Формируем BACnetDateTime для конечного времени
            # Сначала дата
            apdu += bytearray([0x83])  # Tag 8 (Date) = Application Tag 3 (Date)
            apdu += bytearray([
                stop_time.year - 1900,   # Год (от 1900)
                stop_time.month,          # Месяц
                stop_time.day,            # День
                stop_time.weekday() + 1   # День недели (1 = Понедельник)
            ])
            
            # Затем время
            apdu += bytearray([0x84])  # Tag 8 (Time) = Application Tag 4 (Time)
            apdu += bytearray([
                stop_time.hour,           # Час
                stop_time.minute,         # Минута
                stop_time.second,         # Секунда
                int(stop_time.microsecond / 10000)  # Сотые доли секунды
            ])
            
            apdu += bytearray([0x4F])  # Closing Tag 4
            
        elif count > 0:
            # Чтение по позиции (контекстный тег 3)
            apdu += bytearray([0x39, 2])  # By Position
            
            # Референсный индекс (контекстный тег 5) - обычно 1 для начала с первой записи
            apdu += bytearray([0x59, 1])
            
            # Количество записей (контекстный тег 6)
            if count < 0x100:
                apdu += bytearray([0x69, count])
            elif count < 0x10000:
                apdu += bytearray([0x6A]) + struct.pack('>H', count)
            else:
                apdu += bytearray([0x6C]) + struct.pack('>L', count)
        else:
            # Чтение всех записей (контекстный тег 3)
            apdu += bytearray([0x39, 0])  # All
        
        # Строим NPDU (Network Protocol Data Unit)
        # NPDU Version = 1
        # NPDU Control = 0x04 (ожидаем ответ)
        npdu = bytearray([0x01, 0x04])
        
        # Строим BVLC заголовок (BACnet Virtual Link Control)
        # Type = BACnet/IP (0x81)
        # Function = Original-Unicast-NPDU (0x0A)
        # Length = Length of the entire packet
        bvlc_length = len(npdu) + len(apdu) + 4  # 4 bytes for BVLC header
        bvlc = bytearray([0x81, BVLC_ORIGINAL_UNICAST_NPDU]) + struct.pack('>H', bvlc_length)
        
        # Собираем полный пакет
        packet = bvlc + npdu + apdu
        
        # Логируем пакет для отладки
        logger.info(f"Sending ReadRange packet to {self.server_ip}:{self.server_port}")
        logger.debug(f"  Full packet: {binascii.hexlify(packet).decode('ascii')}")
        
        # Отправляем пакет
        try:
            self.socket.sendto(packet, (self.server_ip, self.server_port))
        except Exception as e:
            logger.error(f"Error sending packet: {e}")
            return None
        
        # Ждем ответ для этого invoke_id
        response = self.receive_responses(timeout=5, expected_invoke_id=invoke_id)
        
        # Логируем результат
        if response:
            logger.debug(f"Received response for invoke_id {invoke_id}: {response}")
            
            # Если успешно получили ответ, парсим данные TrendLog
            if response.get('type') == 'complex_ack' and response.get('service_choice') == SERVICE_CONFIRMED_READ_RANGE:
                # Извлекаем данные записей
                if 'trend_log_data' in response:
                    return {
                        'success': True,
                        'device_id': device_id,
                        'object_instance': object_instance,
                        'records': response.get('trend_log_data', []),
                        'total_records': record_count,
                        'returned_records': len(response.get('trend_log_data', []))
                    }
                else:
                    logger.warning("No trend log data in response")
                    return {
                        'success': False,
                        'error': 'No trend log data in response'
                    }
            else:
                logger.warning(f"Unexpected response type: {response.get('type')}")
                return {
                    'success': False,
                    'error': response.get('error', 'Unexpected response type')
                }
        else:
            logger.warning(f"No response received for ReadRange request")
            return {
                'success': False,
                'error': 'No response from device'
            }
            
    def parse_read_range_ack(self, data: bytes, response: Dict) -> None:
        """
        Разбор ответа на ReadRange запрос для TrendLog
        
        Args:
            data: Данные ответа (без заголовков)
            response: Словарь для заполнения результатами
        """
        try:
            # Проверяем наличие данных
            if not data:
                logger.warning("No data in ReadRange ACK")
                response['error'] = "No data in response"
                return
                
            # Указатель на текущую позицию в данных
            offset = 0
            
            # Получаем Object Identifier (должен быть контекстный тег 0)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x00:
                logger.warning("ReadRange ACK: Invalid Object Identifier tag")
                response['error'] = "Invalid Object Identifier tag"
                return
                
            # Пропускаем тег и считываем 4 байта идентификатора объекта
            offset += 1
            if offset + 4 > len(data):
                logger.warning("ReadRange ACK: Object Identifier truncated")
                response['error'] = "Object Identifier truncated"
                return
                
            object_id = struct.unpack('>L', data[offset:offset+4])[0]
            object_type = (object_id >> 22) & 0x3FF
            object_instance = object_id & 0x3FFFFF
            
            offset += 4
            
            # Проверяем, что это TrendLog объект
            if object_type != OBJECT_TREND_LOG:
                logger.warning(f"ReadRange ACK: Object is not a TrendLog, but {object_type}")
                response['error'] = f"Object is not a TrendLog, but {object_type}"
                return
                
            # Получаем Property Identifier (должен быть контекстный тег 1)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x10:
                logger.warning("ReadRange ACK: Invalid Property Identifier tag")
                response['error'] = "Invalid Property Identifier tag"
                return
                
            # Пропускаем тег и считываем идентификатор свойства
            offset += 1
            property_id = data[offset]
            offset += 1
            
            # Ищем данные TrendLog (Array of TrendLogRecord - должен быть контекстный тег 3)
            if offset >= len(data) or (data[offset] & 0xF0) != 0x30:
                logger.warning("ReadRange ACK: Invalid TrendLog data tag")
                response['error'] = "Invalid TrendLog data tag"
                return
                
            # Пропускаем тег и начинаем парсить записи
            offset += 1
            
            # Создаем массив для записей
            trend_records = []
            
            # Парсим записи
            while offset < len(data):
                # Каждая запись - это структура с меткой времени, статусом и значением
                # Проверяем начало записи (должен быть открывающий тег 0)
                if offset >= len(data) or data[offset] != 0x0E:  # Opening Tag 0
                    break  # Конец записей
                    
                offset += 1  # Пропускаем открывающий тег
                
                record = {}
                
                # Читаем timestamp (контекстный тег 1)
                if offset + 1 >= len(data) or (data[offset] & 0xF0) != 0x10:
                    logger.warning("ReadRange ACK: Invalid timestamp tag")
                    break
                    
                offset += 1  # Пропускаем тег
                
                # Читаем BACnetDateTime (сложная структура, состоящая из даты и времени)
                # Открывающий тег 1
                if offset >= len(data) or data[offset] != 0x1E:
                    logger.warning("ReadRange ACK: Invalid DateTime opening tag")
                    break
                    
                offset += 1
                
                # Читаем дату (Application Tag = 3)
                if offset >= len(data) or (data[offset] & 0xF8) != 0x30:
                    logger.warning("ReadRange ACK: Invalid date tag")
                    break
                    
                offset += 1
                
                if offset + 4 > len(data):
                    logger.warning("ReadRange ACK: Date truncated")
                    break
                    
                year = data[offset] + 1900  # Год (от 1900)
                month = data[offset + 1]    # Месяц
                day = data[offset + 2]      # День
                # day_of_week = data[offset + 3]  # День недели
                
                offset += 4
                
                # Читаем время (Application Tag = 4)
                if offset >= len(data) or (data[offset] & 0xF8) != 0x40:
                    logger.warning("ReadRange ACK: Invalid time tag")
                    break
                    
                offset += 1
                
                if offset + 4 > len(data):
                    logger.warning("ReadRange ACK: Time truncated")
                    break
                    
                hour = data[offset]         # Час
                minute = data[offset + 1]   # Минута
                second = data[offset + 2]   # Секунда
                hundredths = data[offset + 3]  # Сотые доли секунды
                
                offset += 4
                
                # Закрывающий тег 1
                if offset >= len(data) or data[offset] != 0x1F:
                    logger.warning("ReadRange ACK: Invalid DateTime closing tag")
                    break
                    
                offset += 1
                
                # Создаем timestamp
                timestamp = datetime.datetime(year, month, day, hour, minute, second, 
                                           hundredths * 10000)  # микросекунды
                record['timestamp'] = timestamp
                
                # Читаем статус (контекстный тег 2)
                if offset >= len(data) and (data[offset] & 0xF0) == 0x20:
                    # Есть статус
                    offset += 1  # Пропускаем тег
                    
                    # Читаем статус (обычно BACnetLogStatus = битовая маска)
                    # Пропускаем на будущее, пока не реализовано
                    # TODO: Реализовать парсинг статуса
                    if (data[offset] & 0xF8) == 0x20:  # BACnetBitString
                        bits = data[offset] & 0x07  # Количество неиспользуемых битов
                        offset += 1
                        length = data[offset]  # Длина битовой строки в байтах
                        offset += 1
                        
                        # Пропускаем байты статуса
                        offset += length
                    else:
                        # Неизвестный формат, пропускаем
                        offset += 1
                        
                # Читаем значение (контекстный тег 3)
                if offset < len(data) and (data[offset] & 0xF0) == 0x30:
                    offset += 1  # Пропускаем тег
                    
                    # Читаем значение (может быть разных типов)
                    if offset < len(data):
                        tag_type = (data[offset] & 0xF8) >> 3
                        
                        # В зависимости от типа тега, парсим значение
                        if tag_type == 0:  # Null
                            record['value'] = None
                            offset += 1
                        elif tag_type == 1:  # Boolean
                            record['value'] = (data[offset] & 0x01) == 1
                            offset += 1
                        elif tag_type == 2:  # UnsignedInteger
                            length = data[offset] & 0x07
                            offset += 1
                            
                            if length == 1 and offset + 1 <= len(data):
                                record['value'] = data[offset]
                                offset += 1
                            elif length == 2 and offset + 2 <= len(data):
                                record['value'] = struct.unpack('>H', data[offset:offset+2])[0]
                                offset += 2
                            elif length == 3 and offset + 3 <= len(data):
                                record['value'] = struct.unpack('>I', b'\x00' + data[offset:offset+3])[0]
                                offset += 3
                            elif length == 4 and offset + 4 <= len(data):
                                record['value'] = struct.unpack('>I', data[offset:offset+4])[0]
                                offset += 4
                            else:
                                logger.warning(f"ReadRange ACK: Invalid UnsignedInteger length {length}")
                                offset += length
                        elif tag_type == 3:  # SignedInteger
                            length = data[offset] & 0x07
                            offset += 1
                            
                            if length == 1 and offset + 1 <= len(data):
                                record['value'] = struct.unpack('b', data[offset:offset+1])[0]
                                offset += 1
                            elif length == 2 and offset + 2 <= len(data):
                                record['value'] = struct.unpack('>h', data[offset:offset+2])[0]
                                offset += 2
                            elif length == 3 and offset + 3 <= len(data):
                                record['value'] = struct.unpack('>i', b'\x00' + data[offset:offset+3])[0]
                                offset += 3
                            elif length == 4 and offset + 4 <= len(data):
                                record['value'] = struct.unpack('>i', data[offset:offset+4])[0]
                                offset += 4
                            else:
                                logger.warning(f"ReadRange ACK: Invalid SignedInteger length {length}")
                                offset += length
                        elif tag_type == 4:  # Real
                            if (data[offset] & 0x07) == 4 and offset + 5 <= len(data):
                                record['value'] = struct.unpack('>f', data[offset+1:offset+5])[0]
                                offset += 5
                            else:
                                logger.warning("ReadRange ACK: Invalid Real format")
                                offset += 1
                        elif tag_type == 7:  # CharacterString
                            length = 0
                            encoding = 0
                            
                            if (data[offset] & 0x07) == 0:  # Длина в текущем байте
                                length = 0
                                offset += 1
                            elif (data[offset] & 0x07) == 1:  # Длина в следующем байте
                                offset += 1
                                if offset < len(data):
                                    length = data[offset]
                                    offset += 1
                            elif (data[offset] & 0x07) == 2:  # Длина в следующих 2 байтах
                                offset += 1
                                if offset + 2 <= len(data):
                                    length = struct.unpack('>H', data[offset:offset+2])[0]
                                    offset += 2
                            else:
                                logger.warning(f"ReadRange ACK: Unsupported string length format {data[offset] & 0x07}")
                                break
                                
                            if offset < len(data):
                                encoding = data[offset]  # Кодировка (0 = ASCII, 1 = UTF-8, ...)
                                offset += 1
                                
                            if offset + length <= len(data):
                                if encoding == 0:  # ASCII
                                    record['value'] = data[offset:offset+length].decode('ascii', errors='replace')
                                elif encoding == 1:  # UTF-8
                                    record['value'] = data[offset:offset+length].decode('utf-8', errors='replace')
                                else:
                                    record['value'] = data[offset:offset+length].hex()
                                    
                                offset += length
                            else:
                                logger.warning("ReadRange ACK: String truncated")
                                break
                        else:
                            logger.warning(f"ReadRange ACK: Unsupported tag type {tag_type}")
                            break
                
                # Проверяем закрывающий тег 0
                if offset >= len(data) or data[offset] != 0x0F:  # Closing Tag 0
                    logger.warning("ReadRange ACK: Missing closing tag for record")
                    break
                    
                offset += 1  # Пропускаем закрывающий тег
                
                # Добавляем запись в результат
                trend_records.append(record)
            
            # Сохраняем записи в ответе
            response['trend_log_data'] = trend_records
            response['success'] = True
            
        except Exception as e:
            logger.error(f"Error parsing ReadRange ACK: {e}")
            import traceback
            logger.error(traceback.format_exc())
            response['error'] = str(e)
            response['success'] = False
    
# ---------------------- Веб-интерфейс и логика приложения ----------------------

# Глобальные переменные для хранения состояния
current_value = None
current_object_name = ""
current_description = ""
last_update_time = None
client_running = True
packet_capture_running = False
packet_capture_thread = None
discovered_objects = {}
client_instance = None
device_id = 0

class BACnetWebHandler(BaseHTTPRequestHandler):
    """Обработчик HTTP-запросов для веб-интерфейса"""
    
    def _set_headers(self, content_type='text/html'):
        """Установка заголовков ответа"""
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')  # CORS для разработки
        self.end_headers()
    
    def do_GET(self):
        """Обработка GET-запросов"""
        # Обработка главной страницы
        if self.path == '/':
            try:
                with open('index.html', 'rb') as file:
                    content = file.read()
                    self._set_headers()
                    self.wfile.write(content)
            except FileNotFoundError:
                # Если файл не найден, отправляем простую HTML-страницу
                self._set_headers()
                self.wfile.write(b"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>BACnet CO2 Client</title>
                    <meta http-equiv="refresh" content="5">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 20px; }
                        .value { font-size: 48px; color: #3498db; text-align: center; margin: 20px 0; }
                        .info { margin: 10px 0; }
                        .label { font-weight: bold; display: inline-block; width: 150px; }
                    </style>
                </head>
                <body>
                    <h1>BACnet CO2 Client</h1>
                    <div class="value" id="value">""" + str(current_value or "--").encode() + b"""</div>
                    <div class="info"><span class="label">Object Name:</span> """ + (current_object_name or "--").encode() + b"""</div>
                    <div class="info"><span class="label">Description:</span> """ + (current_description or "--").encode() + b"""</div>
                    <div class="info"><span class="label">Last Update:</span> """ + (last_update_time.strftime("%Y-%m-%d %H:%M:%S") if last_update_time else "--").encode() + b"""</div>
                </body>
                </html>
                """)
        
        # API для получения текущего значения в формате JSON
        elif self.path == '/value' or self.path == '/api/value':
            try:
                self._set_headers('application/json')
                
                data = {
                    'value': current_value,
                    'timestamp': last_update_time.strftime("%Y-%m-%d %H:%M:%S") if last_update_time else None,
                    'name': current_object_name,
                    'description': current_description,
                    'success': True
                }
                
                # Добавляем информацию о конфигурации
                if client_instance:
                    data['config'] = {
                        'device_id': device_id,
                        'instance': client_instance.config.getint('BACNet_Device', 'analog_input_instance', fallback=0),
                        'target_ip': client_instance.config.get('Network', 'target_ip', fallback='')
                    }
                
                # Добавляем исходное значение, если оно было исправлено
                if hasattr(client_instance, 'last_original_value') and client_instance.last_original_value is not None:
                    data['original_value'] = client_instance.last_original_value
                
                # Отправляем ответ
                self.wfile.write(json.dumps(data).encode())
            
            except Exception as e:
                logger.error(f"Error handling value request: {e}")
                self._set_headers('application/json')
                self.wfile.write(json.dumps({'success': False, 'error': str(e)}).encode())
        
        # Обработка других запросов API
        elif self.path == '/api/objects':
            try:
                self._set_headers('application/json')
                self.wfile.write(json.dumps(discovered_objects).encode())
            except Exception as e:
                logger.error(f"Error handling object request: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        
        elif self.path == '/api/bacnet/who-is':
            # Отправка запроса Who-Is
            try:
                if client_instance:
                    client_instance.send_who_is()
                    self._set_headers('application/json')
                    self.wfile.write(json.dumps({'status': 'success', 'message': 'Who-Is request sent'}).encode())
                else:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b'BACnet client not initialized')
            except Exception as e:
                logger.error(f"Error sending Who-Is: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 Not Found')

def run_web_server(config):
    """Запуск веб-сервера"""
    server_address = (config.get('WEB_Server', 'local_ip'), 
                      int(config.get('WEB_Server', 'local_port')))
    httpd = HTTPServer(server_address, BACnetWebHandler)
    logger.info(f"Starting web server on {server_address[0]}:{server_address[1]}")
    
    # Запуск в отдельном потоке
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return httpd

def poll_bacnet_device(client, config):
    """Периодический опрос BACnet устройства"""
    # Объявляем глобальные переменные
    global current_value, current_object_name, current_description, last_update_time, client_running
    
    # Получаем параметры устройства из конфигурации
    device_id = int(config.get('BACNet_Device', 'device_id'))
    object_instance = int(config.get('BACNet_Device', 'analog_input_instance'))
    interval = int(config.get('Polling', 'interval'))
    max_failures = int(config.get('Polling', 'reconnect_threshold', fallback=3))
    
    logger.info(f"Starting polling thread for device {device_id}, analog input {object_instance}")
    logger.info(f"Polling interval: {interval} seconds, max failures before reconnect: {max_failures}")
    
    failure_count = 0
    
    # Сначала пытаемся обнаружить устройство
    logger.info("Sending initial Who-Is to discover devices")
    devices = client.send_who_is()
    if not devices:
        logger.warning(f"No devices discovered. Will continue trying with configured device ID {device_id}")
    else:
        logger.info(f"Discovered {len(devices)} device(s): {list(devices.keys())}")
        
        # Если наш device_id не в списке найденных, используем первый найденный
        if device_id not in devices and len(devices) > 0:
            new_device_id = list(devices.keys())[0]
            logger.info(f"Configured device ID {device_id} not found, using discovered device ID {new_device_id}")
            device_id = new_device_id
    
    # Пытаемся получить информацию об объекте (имя и описание)
    try:
        # Чтение имени объекта (Object Name)
        logger.info(f"Reading object name for device {device_id}, analog input {object_instance}")
        name_response = client.read_property(device_id, OBJECT_ANALOG_INPUT, object_instance, PROP_OBJECT_NAME)
        
        if name_response and 'value' in name_response:
            current_object_name = name_response['value']
            logger.info(f"Object name: {current_object_name}")
        else:
            logger.warning("Failed to read object name")
            
        time.sleep(1)  # Небольшая пауза между запросами
            
        # Чтение описания объекта (Description)
        logger.info(f"Reading object description for device {device_id}, analog input {object_instance}")
        desc_response = client.read_property(device_id, OBJECT_ANALOG_INPUT, object_instance, PROP_DESCRIPTION)
        
        if desc_response and 'value' in desc_response:
            current_description = desc_response['value']
            logger.info(f"Object description: {current_description}")
        else:
            logger.warning("Failed to read object description")
    
    except Exception as e:
        logger.error(f"Error reading initial object properties: {e}")
    
    # Главный цикл опроса
    while client_running:
        try:
            logger.debug(f"Polling device {device_id}, object {OBJECT_ANALOG_INPUT}:{object_instance}, property {PROP_PRESENT_VALUE}")
            
            # Читаем текущее значение (Present Value)
            response = client.read_property(device_id, OBJECT_ANALOG_INPUT, object_instance, PROP_PRESENT_VALUE)
            
            if response and 'value' in response:
                value = response['value']
                logger.info(f"Successfully read Present Value: {value}")
                
                # Сохраняем информацию об оригинальном значении при необходимости
                if 'original_value' in response:
                    logger.info(f"Value was corrected from original: {response['original_value']}")
                    client.last_original_value = response['original_value']
                else:
                    client.last_original_value = None
                
                # Обновляем глобальную переменную и временную метку
                current_value = value
                last_update_time = datetime.now()
                
                # Сбрасываем счетчик ошибок
                failure_count = 0
            else:
                logger.warning("Failed to read Present Value")
                failure_count += 1
                
                # Если много ошибок подряд, пробуем переобнаружить устройства
                if failure_count >= max_failures:
                    logger.warning(f"Reached {failure_count} consecutive failures, rediscovering devices")
                    
                    # Пробуем отправить Who-Is для переобнаружения устройств
                    devices = client.send_who_is()
                    
                    if devices:
                        logger.info(f"Rediscovered {len(devices)} device(s): {list(devices.keys())}")
                        
                        # Если наш device_id не в списке найденных, используем первый найденный
                        if device_id not in devices and len(devices) > 0:
                            new_device_id = list(devices.keys())[0]
                            logger.info(f"Switching to device ID {new_device_id}")
                            device_id = new_device_id
                    else:
                        logger.warning("No devices rediscovered")
                    
                    # Сбрасываем счетчик ошибок
                    failure_count = 0
            
            # Ждем указанный интервал перед следующим опросом
            time.sleep(interval)
            
        except Exception as e:
            logger.error(f"Error polling device: {e}")
            
            # Увеличиваем счетчик ошибок
            failure_count += 1
            
            # Пауза перед следующей попыткой
            time.sleep(interval)

def signal_handler(sig, frame):
    """Обработчик сигналов для корректного завершения"""
    global client_running
    logger.info("Получен сигнал завершения, останавливаем приложение...")
    client_running = False
    
    # Закрываем клиент, если он инициализирован
    if client_instance:
        client_instance.close()
    
    logger.info("Приложение остановлено")
    sys.exit(0)

def main():
    """
    Основная функция программы.
    Инициализирует клиент BACnet, запускает захват пакетов и веб-сервер.
    """
    try:
        logger.info("Запуск приложения...")
        
        # Обработчик сигналов для корректного завершения
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Инициализация глобальных переменных
        global client_running, client_instance, device_id
        
        client_running = True
        logger.info("Переменные инициализированы")
        
        # Загружаем конфигурацию
        config = configparser.ConfigParser()
        config_file = "config.cfg"
        
        try:
            if os.path.exists(config_file):
                logger.info(f"Загрузка конфигурации из {config_file}")
                config.read(config_file)
                logger.info(f"Конфигурация успешно загружена")
                logger.debug(f"Секции конфигурации: {config.sections()}")
            else:
                logger.warning(f"Файл конфигурации не найден: {config_file}")
                logger.info("Используем настройки по умолчанию")
                
                # Создаем базовую конфигурацию
                config['Network'] = {
                    'target_ip': '172.16.0.255',
                    'target_port': '47808',
                    'local_ip': '0.0.0.0',
                    'local_port': '47809',
                    'ServerIP': '172.16.0.255',
                    'ServerPort': '47808'
                }
                
                config['BACNet_Device'] = {
                    'device_id': '0',
                    'analog_input_instance': '0'
                }
                
                config['WEB_Server'] = {
                    'local_port': '5000',
                    'local_ip': '0.0.0.0'
                }
                
                config['Polling'] = {
                    'interval': '5',
                    'reconnect_threshold': '3'
                }
                
                # Сохраняем конфигурацию
                with open(config_file, 'w') as f:
                    config.write(f)
                logger.info(f"Создан новый файл конфигурации: {config_file}")
        
        except Exception as e:
            logger.error(f"Ошибка при загрузке конфигурации: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return
        
        # Инициализируем BACnet клиент
        try:
            logger.info("Инициализация BACnet клиента...")
            client_instance = BACnetClient(config)
            
            # Обновляем device_id из конфигурации
            device_id = config.getint('BACNet_Device', 'device_id', fallback=0)
            logger.info(f"Целевой Device ID: {device_id}")
        
        except Exception as e:
            logger.error(f"Ошибка при инициализации BACnet клиента: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return
        
        # Запускаем веб-сервер в отдельном потоке
        try:
            logger.info("Запуск веб-сервера...")
            web_server = run_web_server(config)
            logger.info("Веб-сервер запущен успешно")
        
        except Exception as e:
            logger.error(f"Ошибка при запуске веб-сервера: {e}")
        
        # Запускаем поток опроса устройства
        try:
            logger.info("Запуск потока опроса BACnet устройства...")
            
            poll_thread = threading.Thread(
                target=poll_bacnet_device,
                args=(client_instance, config),
                daemon=True
            )
            poll_thread.start()
            logger.info("Поток опроса запущен успешно")
        
        except Exception as e:
            logger.error(f"Ошибка при запуске потока опроса: {e}")
        
        # Основной цикл программы
        try:
            logger.info("Приложение запущено и работает")
            
            while client_running:
                time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Приложение остановлено пользователем")
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
        finally:
            logger.info("Закрытие BACnet клиента...")
            if client_instance:
                client_instance.close()
            logger.info("Приложение завершено")
    
    except KeyboardInterrupt:
        logger.info("Приложение остановлено пользователем")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
    finally:
        logger.info("Закрытие BACnet клиента...")
        if client_instance:
            client_instance.close()
        logger.info("Приложение завершено")

if __name__ == "__main__":
    main()
    