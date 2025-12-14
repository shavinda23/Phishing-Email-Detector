import re
from email_validator import validate_email, EmailNotValidError
from typing import Dict, List

class SenderAnalyzer:
    """Analyze email sender for phishing indicators"""
    
    # Free email providers
    FREE_EMAIL_PROVIDERS = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'aol.com', 'mail.com', 'protonmail.com', 'icloud.com',
        'live.com', 'msn.com', 'zoho.com', 'yandex.com'
    ]
    
    # Legitimate company domains
    COMPANY_DOMAINS = [
        'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'google.com', 'facebook.com', 'netflix.com', 'ebay.com',
        'chase.com', 'wellsfargo.com', 'bankofamerica.com'
    ]
    
    def __init__(self, sender_info: Dict, reply_to: str = ""):
        self.sender_name = sender_info.get('name', '')
        self.sender_email = sender_info.get('email', '')
        self.raw_sender = sender_info.get('raw', '')
        self.reply_to = reply_to
    
    def analyze(self) -> Dict:
        """Perform comprehensive sender analysis"""
        findings = []
        risk_score = 0
        
        # Validate email format
        email_valid = self._validate_email_format()
        if not email_valid['valid']:
            findings.append({
                'type': 'sender',
                'severity': 'high',
                'description': 'Invalid email format',
                'details': email_valid['reason']
            })
            risk_score += 30
        
        # Check for mismatched sender name and email
        mismatch = self._check_name_email_mismatch()
        if mismatch:
            findings.append(mismatch)
            risk_score += 20
        
        # Check for free email provider used by "company"
        free_provider = self._check_free_provider_mismatch()
        if free_provider:
            findings.append(free_provider)
            risk_score += 25
        
        # Check for suspicious email patterns
        suspicious_pattern = self._check_suspicious_patterns()
        if suspicious_pattern:
            findings.append(suspicious_pattern)
            risk_score += 15
        
        # Check reply-to mismatch
        reply_mismatch = self._check_reply_to_mismatch()
        if reply_mismatch:
            findings.append(reply_mismatch)
            risk_score += 20
        
        # Check for lookalike characters
        lookalike = self._check_lookalike_characters()
        if lookalike:
            findings.append(lookalike)
            risk_score += 25
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'sender_suspicious': risk_score > 20
        }
    
    def _validate_email_format(self) -> Dict:
        """Validate email address format"""
        try:
            # Validate email
            valid = validate_email(self.sender_email, check_deliverability=False)
            return {'valid': True, 'reason': ''}
        except EmailNotValidError as e:
            return {'valid': False, 'reason': str(e)}
    
    def _check_name_email_mismatch(self) -> Dict:
        """Check if sender name matches email domain"""
        if not self.sender_name:
            return None
        
        name_lower = self.sender_name.lower()
        email_domain = self.sender_email.split('@')[-1].lower() if '@' in self.sender_email else ''
        
        # Check if name claims to be from a company but email doesn't match
        for company_domain in self.COMPANY_DOMAINS:
            company_name = company_domain.split('.')[0]
            
            if company_name in name_lower and company_domain not in email_domain:
                return {
                    'type': 'sender',
                    'severity': 'high',
                    'description': 'Sender name and email domain mismatch',
                    'details': f"Name suggests '{company_name}' but email is from '{email_domain}'"
                }
        
        return None
    
    def _check_free_provider_mismatch(self) -> Dict:
        """Check if a company is using a free email provider"""
        if not self.sender_name:
            return None
        
        email_domain = self.sender_email.split('@')[-1].lower() if '@' in self.sender_email else ''
        name_lower = self.sender_name.lower()
        
        # Check if using free provider
        is_free_provider = any(provider in email_domain for provider in self.FREE_EMAIL_PROVIDERS)
        
        # Check if name suggests official organization
        official_keywords = ['bank', 'support', 'service', 'team', 'security', 
                           'account', 'admin', 'notification', 'noreply']
        suggests_official = any(keyword in name_lower for keyword in official_keywords)
        
        if is_free_provider and suggests_official:
            return {
                'type': 'sender',
                'severity': 'medium',
                'description': 'Official-sounding sender using free email provider',
                'details': f"'{self.sender_name}' is using {email_domain} (free email service)"
            }
        
        return None
    
    def _check_suspicious_patterns(self) -> Dict:
        """Check for suspicious patterns in email address"""
        email_local = self.sender_email.split('@')[0] if '@' in self.sender_email else self.sender_email
        
        # Check for random character sequences
        if re.search(r'[a-z]{2,}\d{4,}', email_local) or re.search(r'\d{4,}[a-z]{2,}', email_local):
            return {
                'type': 'sender',
                'severity': 'medium',
                'description': 'Suspicious email pattern',
                'details': 'Email contains random-looking character sequences'
            }
        
        # Check for excessive numbers
        digit_count = sum(c.isdigit() for c in email_local)
        if digit_count > len(email_local) * 0.4:
            return {
                'type': 'sender',
                'severity': 'low',
                'description': 'Unusual number of digits in email',
                'details': f'Email local part contains {digit_count} digits'
            }
        
        return None
    
    def _check_reply_to_mismatch(self) -> Dict:
        """Check if Reply-To address differs from From address"""
        if not self.reply_to or self.reply_to == self.sender_email:
            return None
        
        return {
            'type': 'sender',
            'severity': 'medium',
            'description': 'Reply-To address differs from sender',
            'details': f"From: {self.sender_email}, Reply-To: {self.reply_to}"
        }
    
    def _check_lookalike_characters(self) -> Dict:
        """Check for homograph/lookalike characters in domain"""
        email_domain = self.sender_email.split('@')[-1].lower() if '@' in self.sender_email else ''
        
        # Common lookalike substitutions
        lookalikes = {
            '0': 'o',  # zero vs letter o
            '1': 'l',  # one vs letter l
            'rn': 'm',  # rn vs m
        }
        
        for company_domain in self.COMPANY_DOMAINS:
            # Check if domain looks similar to legitimate domain
            for fake, real in lookalikes.items():
                if fake in email_domain:
                    possible_real = email_domain.replace(fake, real)
                    if possible_real == company_domain:
                        return {
                            'type': 'sender',
                            'severity': 'critical',
                            'description': 'Possible homograph/lookalike domain',
                            'details': f"Domain '{email_domain}' may be impersonating '{company_domain}'"
                        }
        
        return None
    
    def get_sender_details(self) -> Dict:
        """Get detailed sender information"""
        email_domain = self.sender_email.split('@')[-1] if '@' in self.sender_email else 'unknown'
        
        return {
            'name': self.sender_name,
            'email': self.sender_email,
            'domain': email_domain,
            'reply_to': self.reply_to,
            'is_free_provider': any(provider in email_domain for provider in self.FREE_EMAIL_PROVIDERS)
        }