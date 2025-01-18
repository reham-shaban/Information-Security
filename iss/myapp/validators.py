import pyclamd
from django.core.exceptions import ValidationError

# validators.py
import pyclamd
from django.core.exceptions import ValidationError

def virus_scan(file):
    """
    Scans a file for viruses using ClamAV via TCP on Windows.
    """
    # Replace with the actual IP and port of the ClamAV daemon
    clamav_host = '127.0.0.1'  # ClamAV daemon running locally
    clamav_port = 3310         # Default ClamAV TCP port

    try:
        # Connect to ClamAV using TCP
        cd = pyclamd.ClamdNetworkSocket(clamav_host, clamav_port)
        cd.ping()  # Check if the ClamAV daemon is running
    except pyclamd.ConnectionError:
        raise ValidationError("ClamAV connection error: Unable to connect to ClamAV daemon")

    # Scan the file
    file.seek(0)  # Ensure the file pointer is at the beginning
    try:
        result = cd.scan_stream(file.read())
        if result:
            raise ValidationError(f"Virus detected: {result}")
    except Exception as e:
        raise ValidationError(f"Error during virus scan: {e}")
    finally:
        file.seek(0)  # Reset the file pointer after scanning


def check_suspicious_filename(file):
    """
    Check if the file has multiple extensions or unusual patterns.
    """
    if file.name.lower().count('.') > 1:  # Multiple dots in filename
        return False
    return True

def validate_file_extension(file):
    """
    التحقق من امتداد الملف
    """
    valid_extensions = ['.docx', '.pdf']
    if not any(file.name.endswith(ext) for ext in valid_extensions):
        raise ValidationError("This file type is not allowed.")

def validate_file_size(file):
    max_size_mb = 5
    if file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"File size exceeds {max_size_mb} MB.")