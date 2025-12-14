import re
from typing import Dict, List

class ContentAnalyzer:
    """Analyze email content for phishing indicators"""
    
    # Urgency/threat keywords
    URGENCY_KEYWORDS = [
        'urgent', 'immediate', 'action required', 'act now', 'quickly',
        'immediately', 'expires', 'limited time', 'hurry', 'fast',
        'don\'t wait', 'right now', 'asap', 'time sensitive'
    ]
    
    THREAT_KEYWORDS = [
        'suspend', 'suspended', 'locked', 'freeze', 'frozen',
        'terminate', 'terminated', 'close', 'closed', 'deactivate',
        'unusual activity', 'suspicious activity', 'unauthorized',
        'security alert', 'fraud', 'fraudulent', 'compromised'
    ]
    
    # Too-good-to-be-true keywords
    OFFER_KEYWORDS = [
        'congratulations', 'winner', 'won', 'prize', 'reward',
        'free', 'gift', 'claim', 'lottery', 'inheritance',
        'selected', 'chosen', 'exclusive', 'guaranteed'
    ]
    
    # Request for sensitive information
    SENSITIVE_REQUEST_KEYWORDS = [
        'password', 'ssn', 'social security', 'credit card',
        'card number', 'cvv', 'pin', 'account number', 'routing number',
        'verify your', 'confirm your', 'update your', 'validate your',
        'verify account', 'confirm identity', 'personal information'
    ]
    
    # Generic greetings
    GENERIC_GREETINGS = [
        'dear customer', 'dear user', 'dear member', 'dear account holder',
        'valued customer', 'valued member', 'hello user', 'greetings'
    ]
    
    def __init__(self, subject: str, body_text: str, body_html: str):
        self.subject = subject.lower() if subject else ""
        self.body_text = body_text.lower() if body_text else ""
        self.body_html = body_html.lower() if body_html else ""
        self.full_content = f"{self.subject} {self.body_text}".lower()
    
    def analyze(self) -> Dict:
        """Perform comprehensive content analysis"""
        findings = []
        risk_score = 0
        
        # Check for urgency language
        urgency_found = self._check_keywords(self.URGENCY_KEYWORDS, "urgency")
        if urgency_found:
            findings.extend(urgency_found)
            risk_score += len(urgency_found) * 15
        
        # Check for threat language
        threats_found = self._check_keywords(self.THREAT_KEYWORDS, "threat")
        if threats_found:
            findings.extend(threats_found)
            risk_score += len(threats_found) * 20
        
        # Check for too-good-to-be-true offers
        offers_found = self._check_keywords(self.OFFER_KEYWORDS, "offer")
        if offers_found:
            findings.extend(offers_found)
            risk_score += len(offers_found) * 15
        
        # Check for requests for sensitive information
        sensitive_requests = self._check_keywords(self.SENSITIVE_REQUEST_KEYWORDS, "sensitive_request")
        if sensitive_requests:
            findings.extend(sensitive_requests)
            risk_score += len(sensitive_requests) * 25
        
        # Check for generic greetings
        generic_greeting = self._check_generic_greeting()
        if generic_greeting:
            findings.append(generic_greeting)
            risk_score += 10
        
        # Check for spelling/grammar issues
        spelling_issues = self._check_spelling_issues()
        if spelling_issues:
            findings.extend(spelling_issues)
            risk_score += len(spelling_issues) * 5
        
        # Check for excessive punctuation
        if self._check_excessive_punctuation():
            findings.append({
                'type': 'formatting',
                'severity': 'low',
                'description': 'Excessive punctuation marks (!!!, ???)',
                'details': 'Legitimate organizations typically use proper punctuation'
            })
            risk_score += 5
        
        # Check for all caps
        if self._check_excessive_caps():
            findings.append({
                'type': 'formatting',
                'severity': 'low',
                'description': 'Excessive use of capital letters',
                'details': 'WRITING IN ALL CAPS is uncommon in legitimate emails'
            })
            risk_score += 5
        
        return {
            'risk_score': min(risk_score, 100),
            'findings': findings,
            'urgency_detected': len(urgency_found) > 0 if urgency_found else False,
            'threats_detected': len(threats_found) > 0 if threats_found else False,
            'sensitive_info_requested': len(sensitive_requests) > 0 if sensitive_requests else False
        }
    
    def _check_keywords(self, keywords: List[str], category: str) -> List[Dict]:
        """Check for presence of specific keywords"""
        findings = []
        found_keywords = []
        
        for keyword in keywords:
            if keyword in self.full_content:
                found_keywords.append(keyword)
        
        if found_keywords:
            severity_map = {
                'urgency': 'medium',
                'threat': 'high',
                'offer': 'medium',
                'sensitive_request': 'critical'
            }
            
            description_map = {
                'urgency': 'Urgency language detected',
                'threat': 'Threatening language detected',
                'offer': 'Too-good-to-be-true offer language',
                'sensitive_request': 'Request for sensitive information'
            }
            
            findings.append({
                'type': 'content',
                'severity': severity_map.get(category, 'medium'),
                'description': description_map.get(category, 'Suspicious keywords'),
                'details': f"Keywords found: {', '.join(found_keywords[:5])}"
            })
        
        return findings
    
    def _check_generic_greeting(self) -> Dict:
        """Check for generic greetings"""
        for greeting in self.GENERIC_GREETINGS:
            if greeting in self.full_content:
                return {
                    'type': 'content',
                    'severity': 'low',
                    'description': 'Generic greeting used',
                    'details': f"Found '{greeting}' - legitimate emails often use your actual name"
                }
        return None
    
    def _check_spelling_issues(self) -> List[Dict]:
        """Check for common spelling issues in phishing emails"""
        findings = []
        
        # Common misspellings in phishing
        misspellings = {
            'recieve': 'receive',
            'occured': 'occurred',
            'seperate': 'separate',
            'untill': 'until',
            'transfered': 'transferred'
        }
        
        for wrong, correct in misspellings.items():
            if wrong in self.full_content:
                findings.append({
                    'type': 'content',
                    'severity': 'low',
                    'description': 'Spelling error detected',
                    'details': f"'{wrong}' should be '{correct}'"
                })
        
        return findings
    
    def _check_excessive_punctuation(self) -> bool:
        """Check for excessive punctuation marks"""
        # Check for multiple exclamation or question marks
        if re.search(r'[!?]{2,}', self.full_content):
            return True
        return False
    
    def _check_excessive_caps(self) -> bool:
        """Check for excessive use of capital letters"""
        # Check for words with 5+ consecutive caps
        if re.search(r'\b[A-Z]{5,}\b', self.subject + " " + self.body_text):
            return True
        
        # Check if more than 30% of letters are capitalized
        if self.body_text:
            letters = re.findall(r'[a-zA-Z]', self.body_text)
            if len(letters) > 20:  # Only check if there's substantial text
                caps_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
                if caps_ratio > 0.3:
                    return True
        
        return False
    
    def get_content_summary(self) -> Dict:
        """Get summary of email content"""
        return {
            'subject': self.subject,
            'body_length': len(self.body_text),
            'has_html': bool(self.body_html),
            'word_count': len(self.body_text.split()) if self.body_text else 0
        }