import os
from typing import List, Dict

class AttachmentAnalyzer:
    """Analyze email attachments for phishing indicators"""
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs',
        '.js', '.jar', '.wsf', '.ps1', '.app', '.deb', '.rpm'
    ]
    
    # Suspicious extensions
    SUSPICIOUS_EXTENSIONS = [
        '.zip', '.rar', '.7z', '.gz', '.tar',  # Archives
        '.docm', '.xlsm', '.pptm',  # Office files with macros
        '.html', '.htm', '.hta',  # HTML applications
        '.iso', '.img',  # Disk images
    ]
    
    # Double extension patterns
    DOUBLE_EXTENSION_PATTERN = [
        '.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe',
        '.pdf.js', '.doc.js', '.jpg.js'
    ]
    
    def __init__(self, attachments: List[Dict]):
        self.attachments = attachments
    
    def analyze(self) -> Dict:
        """Perform comprehensive attachment analysis"""
        if not self.attachments:
            return {
                'risk_score': 0,
                'findings': [],
                'has_dangerous_attachments': False
            }
        
        findings = []
        risk_score = 0
        has_dangerous = False
        
        for attachment in self.attachments:
            filename = attachment.get('filename', '').lower()
            content_type = attachment.get('content_type', '')
            file_size = attachment.get('size', 0)
            
            # Check for dangerous extensions
            dangerous = self._check_dangerous_extension(filename)
            if dangerous:
                findings.append(dangerous)
                risk_score += 40
                has_dangerous = True
            
            # Check for suspicious extensions
            suspicious = self._check_suspicious_extension(filename)
            if suspicious:
                findings.append(suspicious)
                risk_score += 20
            
            # Check for double extensions
            double_ext = self._check_double_extension(filename)
            if double_ext:
                findings.append(double_ext)
                risk_score += 30
                has_dangerous = True
            
            # Check for password-protected archives
            if self._is_password_protected_archive(filename, content_type):
                findings.append({
                    'type': 'attachment',
                    'severity': 'high',
                    'description': 'Password-protected archive detected',
                    'details': f"'{filename}' - often used to bypass security scans"
                })
                risk_score += 25
            
            # Check for mismatched extension and content type
            mismatch = self._check_content_type_mismatch(filename, content_type)
            if mismatch:
                findings.append(mismatch)
                risk_score += 20
            
            # Check for unusually large files
            if file_size > 10 * 1024 * 1024:  # 10MB
                findings.append({
                    'type': 'attachment',
                    'severity': 'low',
                    'description': 'Unusually large attachment',
                    'details': f"'{filename}' is {file_size / (1024*1024):.1f}MB"
                })
                risk_score += 5
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'has_dangerous_attachments': has_dangerous,
            'attachment_count': len(self.attachments)
        }
    
    def _check_dangerous_extension(self, filename: str) -> Dict:
        """Check for dangerous file extensions"""
        for ext in self.DANGEROUS_EXTENSIONS:
            if filename.endswith(ext):
                return {
                    'type': 'attachment',
                    'severity': 'critical',
                    'description': 'Dangerous executable file detected',
                    'details': f"'{filename}' has potentially harmful extension '{ext}'"
                }
        return None
    
    def _check_suspicious_extension(self, filename: str) -> Dict:
        """Check for suspicious file extensions"""
        for ext in self.SUSPICIOUS_EXTENSIONS:
            if filename.endswith(ext):
                # Check for Office files with macros
                if ext in ['.docm', '.xlsm', '.pptm']:
                    return {
                        'type': 'attachment',
                        'severity': 'high',
                        'description': 'Office file with macros detected',
                        'details': f"'{filename}' can contain malicious macro code"
                    }
                
                # Check for archives
                if ext in ['.zip', '.rar', '.7z', '.gz', '.tar']:
                    return {
                        'type': 'attachment',
                        'severity': 'medium',
                        'description': 'Compressed archive detected',
                        'details': f"'{filename}' may contain hidden malicious files"
                    }
        
        return None
    
    def _check_double_extension(self, filename: str) -> Dict:
        """Check for double extension trick"""
        for pattern in self.DOUBLE_EXTENSION_PATTERN:
            if pattern in filename:
                return {
                    'type': 'attachment',
                    'severity': 'critical',
                    'description': 'Double extension detected',
                    'details': f"'{filename}' uses deceptive naming to hide true file type"
                }
        
        # General double extension check
        parts = filename.split('.')
        if len(parts) > 2:
            # Check if second-to-last part looks like a file extension
            common_exts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt']
            if parts[-2] in common_exts and parts[-1] in ['exe', 'js', 'bat', 'cmd']:
                return {
                    'type': 'attachment',
                    'severity': 'critical',
                    'description': 'Suspicious double extension',
                    'details': f"'{filename}' may be hiding malicious executable"
                }
        
        return None
    
    def _is_password_protected_archive(self, filename: str, content_type: str) -> bool:
        """Check if file is likely a password-protected archive"""
        # This is a heuristic - we can't definitively know without opening the file
        # But we can flag archives which are commonly password-protected in phishing
        archive_extensions = ['.zip', '.rar', '.7z']
        return any(filename.endswith(ext) for ext in archive_extensions)
    
    def _check_content_type_mismatch(self, filename: str, content_type: str) -> Dict:
        """Check if filename extension matches content type"""
        # Simple extension to MIME type mapping
        mime_map = {
            '.pdf': 'application/pdf',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.zip': 'application/zip',
            '.jpg': 'image/jpeg',
            '.png': 'image/png'
        }
        
        for ext, expected_mime in mime_map.items():
            if filename.endswith(ext):
                if content_type and expected_mime not in content_type:
                    return {
                        'type': 'attachment',
                        'severity': 'medium',
                        'description': 'Extension and content type mismatch',
                        'details': f"'{filename}' claims to be {ext} but content type is {content_type}"
                    }
        
        return None
    
    def get_attachment_summary(self) -> List[Dict]:
        """Get summary of all attachments"""
        summary = []
        for attachment in self.attachments:
            summary.append({
                'filename': attachment.get('filename', 'unknown'),
                'type': attachment.get('content_type', 'unknown'),
                'size': f"{attachment.get('size', 0) / 1024:.1f} KB"
            })
        return summary