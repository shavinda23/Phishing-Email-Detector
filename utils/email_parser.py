import re
import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from typing import Dict, List

class EmailParser:
    """Parse email content and extract relevant information"""
    
    def __init__(self, email_content: str, is_file: bool = False):
        self.raw_content = email_content
        self.is_file = is_file
        self.parsed_email = None
        self.parse()
    
    def parse(self):
        """Parse the email content"""
        if self.is_file:
            # Parse .eml file
            self.parsed_email = BytesParser(policy=policy.default).parsebytes(
                self.raw_content.encode()
            )
        else:
            # Parse plain text email
            self.parsed_email = email.message_from_string(
                self.raw_content,
                policy=policy.default
            )
    
    def get_sender(self) -> Dict[str, str]:
        """Extract sender information"""
        from_header = self.parsed_email.get('From', '')
        
        # Extract name and email
        match = re.search(r'(.+?)\s*<(.+?)>', from_header)
        if match:
            return {
                'name': match.group(1).strip().strip('"'),
                'email': match.group(2).strip(),
                'raw': from_header
            }
        else:
            return {
                'name': '',
                'email': from_header.strip(),
                'raw': from_header
            }
    
    def get_subject(self) -> str:
        """Extract email subject"""
        return self.parsed_email.get('Subject', '')
    
    def get_body(self) -> Dict[str, str]:
        """Extract email body (text and HTML)"""
        text_body = ""
        html_body = ""
        
        if self.parsed_email.is_multipart():
            for part in self.parsed_email.walk():
                content_type = part.get_content_type()
                
                if content_type == 'text/plain':
                    text_body = part.get_content()
                elif content_type == 'text/html':
                    html_body = part.get_content()
        else:
            content_type = self.parsed_email.get_content_type()
            if content_type == 'text/plain':
                text_body = self.parsed_email.get_content()
            elif content_type == 'text/html':
                html_body = self.parsed_email.get_content()
        
        return {
            'text': text_body,
            'html': html_body
        }
    
    def extract_urls(self) -> List[str]:
        """Extract all URLs from email body"""
        urls = []
        body = self.get_body()
        
        # Extract from text body
        if body['text']:
            urls.extend(re.findall(
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                body['text']
            ))
        
        # Extract from HTML body
        if body['html']:
            soup = BeautifulSoup(body['html'], 'html.parser')
            for link in soup.find_all('a', href=True):
                urls.append(link['href'])
        
        return list(set(urls))  # Remove duplicates
    
    def get_attachments(self) -> List[Dict[str, str]]:
        """Extract attachment information"""
        attachments = []
        
        if self.parsed_email.is_multipart():
            for part in self.parsed_email.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_content())
                        })
        
        return attachments
    
    def get_headers(self) -> Dict[str, str]:
        """Extract important email headers"""
        return {
            'from': self.parsed_email.get('From', ''),
            'to': self.parsed_email.get('To', ''),
            'date': self.parsed_email.get('Date', ''),
            'reply_to': self.parsed_email.get('Reply-To', ''),
            'return_path': self.parsed_email.get('Return-Path', ''),
            'received': self.parsed_email.get('Received', ''),
        }