from typing import Dict, List

class PhishingScorer:
    """Calculate overall phishing risk score and determine threat level"""
    
    def __init__(self):
        self.weights = {
            'url': 0.25,
            'content': 0.25,
            'sender': 0.30,
            'attachment': 0.20
        }
    
    def calculate_overall_score(self, analysis_results: Dict) -> Dict:
        """Calculate weighted overall risk score"""
        
        # Extract individual scores
        url_score = analysis_results.get('url_analysis', {}).get('risk_score', 0)
        content_score = analysis_results.get('content_analysis', {}).get('risk_score', 0)
        sender_score = analysis_results.get('sender_analysis', {}).get('risk_score', 0)
        attachment_score = analysis_results.get('attachment_analysis', {}).get('risk_score', 0)
        
        # Calculate weighted score
        weighted_score = (
            url_score * self.weights['url'] +
            content_score * self.weights['content'] +
            sender_score * self.weights['sender'] +
            attachment_score * self.weights['attachment']
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(weighted_score)
        
        # Get threat color
        threat_color = self._get_threat_color(threat_level)
        
        # Compile all findings
        all_findings = self._compile_findings(analysis_results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis_results, threat_level)
        
        return {
            'overall_score': round(weighted_score, 1),
            'threat_level': threat_level,
            'threat_color': threat_color,
            'component_scores': {
                'url': url_score,
                'content': content_score,
                'sender': sender_score,
                'attachment': attachment_score
            },
            'all_findings': all_findings,
            'critical_findings': [f for f in all_findings if f.get('severity') == 'critical'],
            'high_findings': [f for f in all_findings if f.get('severity') == 'high'],
            'recommendations': recommendations
        }
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level based on score"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "SAFE"
    
    def _get_threat_color(self, threat_level: str) -> str:
        """Get color for threat level"""
        colors = {
            'CRITICAL': '#DC2626',  # Red
            'HIGH': '#EA580C',      # Orange
            'MEDIUM': '#F59E0B',    # Amber
            'LOW': '#10B981',       # Green
            'SAFE': '#059669'       # Dark green
        }
        return colors.get(threat_level, '#6B7280')
    
    def _compile_findings(self, analysis_results: Dict) -> List[Dict]:
        """Compile all findings from all analyzers"""
        all_findings = []
        
        # Get findings from each analyzer
        url_findings = analysis_results.get('url_analysis', {}).get('findings', [])
        content_findings = analysis_results.get('content_analysis', {}).get('findings', [])
        sender_findings = analysis_results.get('sender_analysis', {}).get('findings', [])
        attachment_findings = analysis_results.get('attachment_analysis', {}).get('findings', [])
        
        # Combine all findings
        all_findings.extend(url_findings)
        all_findings.extend(content_findings)
        all_findings.extend(sender_findings)
        all_findings.extend(attachment_findings)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
        
        return all_findings
    
    def _generate_recommendations(self, analysis_results: Dict, threat_level: str) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        if threat_level in ['CRITICAL', 'HIGH']:
            recommendations.append("🚨 DO NOT click any links or open attachments in this email")
            recommendations.append("🗑️ Delete this email immediately")
            recommendations.append("📧 Report this email to your IT security team or email provider")
        
        # Check for specific issues and provide targeted recommendations
        url_analysis = analysis_results.get('url_analysis', {})
        content_analysis = analysis_results.get('content_analysis', {})
        sender_analysis = analysis_results.get('sender_analysis', {})
        attachment_analysis = analysis_results.get('attachment_analysis', {})
        
        # URL-specific recommendations
        if url_analysis.get('suspicious_urls'):
            recommendations.append("🔗 Suspicious URLs detected - verify links by hovering over them before clicking")
            recommendations.append("🌐 Manually type website addresses instead of clicking email links")
        
        # Content-specific recommendations
        if content_analysis.get('sensitive_info_requested'):
            recommendations.append("🔒 Legitimate organizations never ask for passwords or sensitive info via email")
            recommendations.append("📞 Contact the company directly using official contact information")
        
        if content_analysis.get('urgency_detected') or content_analysis.get('threats_detected'):
            recommendations.append("⏰ Be wary of urgent requests - scammers create artificial time pressure")
        
        # Sender-specific recommendations
        if sender_analysis.get('sender_suspicious'):
            recommendations.append("👤 Verify sender identity through alternative channels")
            recommendations.append("📧 Check sender's email address carefully for slight misspellings")
        
        # Attachment-specific recommendations
        if attachment_analysis.get('has_dangerous_attachments'):
            recommendations.append("📎 DO NOT open suspicious attachments - they may contain malware")
            recommendations.append("🛡️ Scan any attachments with antivirus before opening")
        
        # General recommendations for medium/low threats
        if threat_level in ['MEDIUM', 'LOW']:
            recommendations.append("🔍 Exercise caution and verify sender authenticity")
            recommendations.append("✅ When in doubt, contact the sender through known channels")
        
        # Safe emails
        if threat_level == 'SAFE':
            recommendations.append("✅ This email appears legitimate based on automated analysis")
            recommendations.append("💡 Still exercise normal email safety practices")
        
        # Always include general advice
        recommendations.append("🎓 Remember: If something feels off, trust your instincts")
        
        return recommendations
    
    def get_severity_stats(self, findings: List[Dict]) -> Dict:
        """Get statistics about finding severities"""
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in stats:
                stats[severity] += 1
        
        return stats