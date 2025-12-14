import streamlit as st
from utils.email_parser import EmailParser
from analyzers.url_analyzer import URLAnalyzer
from analyzers.content_analyzer import ContentAnalyzer
from analyzers.sender_analyzer import SenderAnalyzer
from analyzers.attachment_analyzer import AttachmentAnalyzer
from utils.scoring import PhishingScorer

# Page configuration
st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🎣",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
<style>
    /* Import modern font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    /* Global styles */
    * {
        font-family: 'Inter', sans-serif;
    }
    
    /* Main header with animated gradient */
    .main-header {
        font-size: 3.5rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 0.5rem;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 25%, #f093fb 50%, #f5576c 75%, #ffc371 100%);
        background-size: 300% 300%;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        animation: gradient 8s ease infinite;
        letter-spacing: -0.5px;
    }
    
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .subtitle {
        text-align: center;
        color: #6B7280;
        font-size: 1.1rem;
        margin-bottom: 2.5rem;
        font-weight: 500;
    }
    
    /* Modern threat card with glassmorphism */
    .threat-card {
        padding: 2.5rem;
        border-radius: 20px;
        margin: 2rem 0;
        text-align: center;
        backdrop-filter: blur(10px);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.18);
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    
    .threat-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
    }
    
    /* Enhanced finding cards */
    .finding-card {
        padding: 1.2rem;
        border-radius: 12px;
        margin: 0.8rem 0;
        border-left: 5px solid;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        transition: all 0.3s ease;
        backdrop-filter: blur(5px);
    }
    
    .finding-card:hover {
        transform: translateX(5px);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
    }
    
    .critical { 
        border-left-color: #DC2626; 
        background: linear-gradient(135deg, #FEE2E2 0%, #FECACA 100%);
    }
    .high { 
        border-left-color: #EA580C; 
        background: linear-gradient(135deg, #FFEDD5 0%, #FED7AA 100%);
    }
    .medium { 
        border-left-color: #F59E0B; 
        background: linear-gradient(135deg, #FEF3C7 0%, #FDE68A 100%);
    }
    .low { 
        border-left-color: #10B981; 
        background: linear-gradient(135deg, #D1FAE5 0%, #A7F3D0 100%);
    }
    
    /* Modern metric cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 16px;
        text-align: center;
        color: white;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        transition: all 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    
    /* Animated button */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.8rem 2rem;
        font-weight: 600;
        font-size: 1.1rem;
        transition: all 0.3s ease;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
    }
    
    /* Enhanced tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #F9FAFB;
        border-radius: 12px;
        padding: 0.5rem;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 0.8rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white !important;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    
    [data-testid="stSidebar"] * {
        color: white !important;
    }
    
    /* Text area styling */
    .stTextArea textarea {
        border-radius: 12px;
        border: 2px solid #E5E7EB;
        font-family: 'Monaco', 'Menlo', monospace;
        transition: all 0.3s ease;
    }
    
    .stTextArea textarea:focus {
        border-color: #667eea;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
    }
    
    /* Expander styling */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #F9FAFB 0%, #F3F4F6 100%);
        border-radius: 12px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .streamlit-expanderHeader:hover {
        background: linear-gradient(135deg, #E5E7EB 0%, #D1D5DB 100%);
    }
    
    /* Success/Error messages */
    .stSuccess {
        background: linear-gradient(135deg, #D1FAE5 0%, #A7F3D0 100%);
        border-radius: 12px;
        border-left: 5px solid #10B981;
    }
    
    .stError {
        background: linear-gradient(135deg, #FEE2E2 0%, #FECACA 100%);
        border-radius: 12px;
        border-left: 5px solid #DC2626;
    }
    
    /* Radio buttons */
    .stRadio > label {
        font-weight: 600;
        color: #374151;
    }
    
    /* Divider */
    hr {
        margin: 2rem 0;
        border: none;
        height: 2px;
        background: linear-gradient(90deg, transparent, #667eea, transparent);
    }
    
    /* Pulse animation for critical findings */
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
    
    .critical {
        animation: pulse 2s ease-in-out infinite;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header with icon
    st.markdown('<h1 class="main-header">🛡️ Phishing Email Detector</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">🔒 Advanced AI-Powered Email Security Analysis | Protect Your Digital Identity</p>', unsafe_allow_html=True)
    
    # Sidebar information with enhanced styling
    with st.sidebar:
        st.markdown("### ℹ️ About This Tool")
        st.markdown("""
        <div style='background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px; margin-bottom: 1rem;'>
        This advanced security tool analyzes emails for phishing indicators using multi-layer detection:
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        **🔍 Detection Layers:**
        - 🔗 **URL Analysis** - Shorteners, typosquatting, malicious domains
        - 📝 **Content Analysis** - Urgency tactics, threats, social engineering
        - 👤 **Sender Verification** - Spoofing, domain mismatches
        - 📎 **Attachment Safety** - Dangerous file types, hidden executables
        """)
        
        st.markdown("---")
        
        st.markdown("### 🚀 Quick Start")
        st.markdown("""
        **Step 1:** Paste email content below  
        **Step 2:** Click "Analyze Email"  
        **Step 3:** Review threat assessment  
        **Step 4:** Follow recommendations
        """)
        
        st.markdown("---")
        
        st.markdown("### 🛡️ Security Best Practices")
        st.markdown("""
        ✅ Verify sender before clicking links  
        ✅ Hover over URLs to see destination  
        ✅ Never share passwords via email  
        ✅ Enable two-factor authentication  
        ✅ Report suspicious emails  
        ✅ Keep software updated
        """)
        
        st.markdown("---")
        
        st.markdown("""
        <div style='background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px; text-align: center;'>
        <small>💡 Built with Python & Streamlit<br>🔒 Your privacy is protected</small>
        </div>
        """, unsafe_allow_html=True)
    
    # Main content area with enhanced tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Analyze Email", "📊 Sample Emails", "🎓 Learn More"])
    
    with tab1:
        # Add a nice info banner
        st.markdown("""
        <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                    padding: 1.5rem; border-radius: 12px; color: white; margin-bottom: 2rem;
                    box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);'>
            <h3 style='margin: 0; color: white;'>📧 Email Security Scanner</h3>
            <p style='margin: 0.5rem 0 0 0; opacity: 0.9;'>
                Paste your email content below or upload an .eml file for comprehensive security analysis
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        # Input method selection
        input_method = st.radio(
            "Choose input method:",
            ["Paste Email Text", "Upload .eml File"],
            horizontal=True
        )
        
        email_content = ""
        
        if input_method == "Paste Email Text":
            email_content = st.text_area(
                "Paste your email content here:",
                height=300,
                placeholder="""From: support@paypal-secure.com
To: user@example.com
Subject: URGENT: Your Account Will Be Suspended

Dear Valued Customer,

We have detected unusual activity on your PayPal account. Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to verify: http://paypal-verify.tk/login

Thank you,
PayPal Security Team"""
            )
        else:
            uploaded_file = st.file_uploader("Choose an .eml file", type=['eml', 'txt'])
            if uploaded_file:
                email_content = uploaded_file.read().decode('utf-8', errors='ignore')
                st.success("File uploaded successfully!")
        
        # Analyze button with icon
        if st.button("🔍 Analyze Email Security", type="primary", use_container_width=True):
            if not email_content.strip():
                st.error("⚠️ Please provide email content to analyze!")
            else:
                analyze_email(email_content)
    
    with tab2:
        show_sample_emails()
    
    with tab3:
        show_learn_more()

def analyze_email(email_content: str):
    """Main email analysis function"""
    
    with st.spinner("🔄 Analyzing email... This may take a moment..."):
        try:
            # Parse email
            parser = EmailParser(email_content)
            
            # Extract components
            sender_info = parser.get_sender()
            subject = parser.get_subject()
            body = parser.get_body()
            urls = parser.extract_urls()
            attachments = parser.get_attachments()
            headers = parser.get_headers()
            
            # Run analyzers
            url_analyzer = URLAnalyzer(urls)
            url_analysis = url_analyzer.analyze()
            
            content_analyzer = ContentAnalyzer(subject, body['text'], body['html'])
            content_analysis = content_analyzer.analyze()
            
            sender_analyzer = SenderAnalyzer(sender_info, headers.get('reply_to', ''))
            sender_analysis = sender_analyzer.analyze()
            
            attachment_analyzer = AttachmentAnalyzer(attachments)
            attachment_analysis = attachment_analyzer.analyze()
            
            # Calculate overall score
            analysis_results = {
                'url_analysis': url_analysis,
                'content_analysis': content_analysis,
                'sender_analysis': sender_analysis,
                'attachment_analysis': attachment_analysis
            }
            
            scorer = PhishingScorer()
            overall_results = scorer.calculate_overall_score(analysis_results)
            
            # Display results
            display_results(overall_results, sender_info, subject, urls, attachments)
            
        except Exception as e:
            st.error(f"❌ Error analyzing email: {str(e)}")
            st.exception(e)

def display_results(results: dict, sender_info: dict, subject: str, urls: list, attachments: list):
    """Display analysis results with enhanced visuals"""
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #10B981 0%, #059669 100%); 
                padding: 1rem; border-radius: 12px; color: white; text-align: center;
                box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3); margin-bottom: 2rem;'>
        <h3 style='margin: 0; color: white;'>✅ Analysis Complete!</h3>
        <p style='margin: 0.5rem 0 0 0; opacity: 0.9;'>Comprehensive security scan finished</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Overall threat level with enhanced design
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        threat_level = results['threat_level']
        threat_color = results['threat_color']
        overall_score = results['overall_score']
        
        # Animated threat indicator
        threat_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': '✓',
            'SAFE': '✅'
        }
        
        st.markdown(f"""
        <div class="threat-card" style="background: {threat_color}15; border: 3px solid {threat_color};">
            <div style="font-size: 4rem; margin-bottom: 1rem;">{threat_emoji.get(threat_level, '⚠️')}</div>
            <h2 style="color: {threat_color}; margin: 0; font-size: 2.5rem; font-weight: 800;">{threat_level} THREAT</h2>
            <h1 style="color: {threat_color}; margin: 1rem 0; font-size: 4rem; font-weight: 800;">{overall_score}%</h1>
            <p style="color: #6B7280; margin: 0; font-size: 1.2rem; font-weight: 600;">Risk Score</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Component scores with modern cards
    st.markdown("### 📊 Detailed Security Analysis")
    
    col1, col2, col3, col4 = st.columns(4)
    
    components = [
        ("🔗", "URLs", results['component_scores']['url'], len(urls), col1),
        ("📝", "Content", results['component_scores']['content'], None, col2),
        ("👤", "Sender", results['component_scores']['sender'], None, col3),
        ("📎", "Attachments", results['component_scores']['attachment'], len(attachments), col4)
    ]
    
    for emoji, label, score, count, col in components:
        with col:
            count_text = f"{count} found" if count is not None else ""
            color = "#DC2626" if score >= 70 else "#EA580C" if score >= 50 else "#F59E0B" if score >= 30 else "#10B981"
            
            st.markdown(f"""
            <div style='background: linear-gradient(135deg, {color}15 0%, {color}25 100%);
                        padding: 1.5rem; border-radius: 16px; text-align: center;
                        border: 2px solid {color}40;
                        box-shadow: 0 4px 15px {color}20;
                        transition: transform 0.3s ease;'>
                <div style='font-size: 2.5rem; margin-bottom: 0.5rem;'>{emoji}</div>
                <div style='font-size: 2rem; font-weight: 800; color: {color}; margin-bottom: 0.3rem;'>{score}%</div>
                <div style='font-weight: 600; color: #374151; margin-bottom: 0.3rem;'>{label}</div>
                <div style='font-size: 0.85rem; color: #6B7280;'>{count_text}</div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Email details with enhanced design
    with st.expander("📧 Email Details", expanded=True):
        st.markdown(f"""
        <div style='background: #F9FAFB; padding: 1.5rem; border-radius: 12px; border-left: 5px solid #667eea;'>
            <p style='margin: 0.5rem 0;'><strong>From:</strong> {sender_info['name']} &lt;{sender_info['email']}&gt;</p>
            <p style='margin: 0.5rem 0;'><strong>Subject:</strong> {subject}</p>
            <p style='margin: 0.5rem 0;'><strong>URLs Found:</strong> {len(urls)}</p>
        </div>
        """, unsafe_allow_html=True)
        
        if urls:
            st.markdown("**🔗 Detected URLs:**")
            for i, url in enumerate(urls[:5], 1):
                st.code(f"{i}. {url}", language=None)
    
    # Findings with enhanced styling
    st.markdown("### 🔍 Security Findings")
    
    all_findings = results['all_findings']
    
    if not all_findings:
        st.markdown("""
        <div style='background: linear-gradient(135deg, #D1FAE5 0%, #A7F3D0 100%);
                    padding: 2rem; border-radius: 12px; text-align: center;
                    border: 2px solid #10B981;
                    box-shadow: 0 4px 15px rgba(16, 185, 129, 0.2);'>
            <div style='font-size: 3rem; margin-bottom: 1rem;'>✅</div>
            <h3 style='color: #065F46; margin: 0;'>No Security Issues Detected!</h3>
            <p style='color: #047857; margin-top: 0.5rem;'>This email appears to be legitimate</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Group findings by severity
        severity_groups = {
            'critical': {'label': '🚨 Critical Issues', 'findings': []},
            'high': {'label': '⚠️ High Risk Issues', 'findings': []},
            'medium': {'label': '⚡ Medium Risk Issues', 'findings': []},
            'low': {'label': 'ℹ️ Low Risk Issues', 'findings': []}
        }
        
        for finding in all_findings:
            severity = finding.get('severity', 'low')
            if severity in severity_groups:
                severity_groups[severity]['findings'].append(finding)
        
        for severity, group in severity_groups.items():
            if group['findings']:
                st.markdown(f"**{group['label']}**")
                
                for finding in group['findings']:
                    icon_map = {
                        'critical': '🚨',
                        'high': '⚠️',
                        'medium': '⚡',
                        'low': 'ℹ️'
                    }
                    
                    st.markdown(f"""
                    <div class="finding-card {severity}">
                        <div style='display: flex; align-items: start; gap: 1rem;'>
                            <div style='font-size: 1.5rem;'>{icon_map.get(severity, 'ℹ️')}</div>
                            <div style='flex: 1;'>
                                <strong style='font-size: 1.1rem; color: #1F2937;'>{finding['description']}</strong><br>
                                <small style='color: #6B7280; margin-top: 0.5rem; display: block;'>{finding['details']}</small>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Recommendations with modern design
    st.markdown("### 💡 Security Recommendations")
    
    st.markdown("""
    <div style='background: linear-gradient(135deg, #EEF2FF 0%, #E0E7FF 100%);
                padding: 1.5rem; border-radius: 12px;
                border-left: 5px solid #667eea;
                box-shadow: 0 2px 8px rgba(102, 126, 234, 0.1);'>
    """, unsafe_allow_html=True)
    
    for i, recommendation in enumerate(results['recommendations'], 1):
        st.markdown(f"**{recommendation}**")
    
    st.markdown("</div>", unsafe_allow_html=True)

def show_sample_emails():
    """Show sample phishing emails for testing with enhanced design"""
    st.markdown("### 📊 Test with Sample Emails")
    st.markdown("""
    <div style='background: linear-gradient(135deg, #FEF3C7 0%, #FDE68A 100%);
                padding: 1rem; border-radius: 12px; margin-bottom: 2rem;
                border-left: 5px solid #F59E0B;'>
        <p style='margin: 0; color: #92400E;'><strong>💡 Quick Test:</strong> Click on any sample below to automatically load it for analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    samples = {
        "🚨 Critical - Obvious PayPal Scam": """From: security@paypal-verify.tk
To: victim@email.com
Subject: URGENT: Account Suspended - Verify Now!!!

Dear Customer,

Your PayPal account has been SUSPENDED due to unusual activity detected. You have 24 HOURS to verify your information or your account will be PERMANENTLY CLOSED.

CLICK HERE IMMEDIATELY: http://bit.ly/paypal-verify-urgent

You must provide:
- Full Name
- Password
- Credit Card Number
- SSN

Failure to comply will result in account termination.

PayPal Security Team
DO NOT REPLY TO THIS EMAIL""",
        
        "⚠️ High Risk - Sophisticated Spear Phishing": """From: IT Support <it.support@gmail.com>
To: employee@company.com
Subject: Password Reset Required

Hi,

As part of our security upgrade, all employees must reset their passwords by end of day. Please click the link below to update your credentials:

https://company-portal-secure.xyz/reset

This is mandatory for all staff. Contact IT if you have issues.

Best regards,
IT Department""",
        
        "✅ Safe - Legitimate GitHub Notification": """From: notifications@github.com
To: developer@email.com
Subject: [GitHub] New pull request on your repository

Hello,

A new pull request has been opened on your repository "awesome-project":

Pull Request #42: Fix authentication bug
View on GitHub: https://github.com/user/awesome-project/pull/42

Thanks,
GitHub Team"""
    }
    
    for title, content in samples.items():
        with st.expander(title, expanded=False):
            st.code(content, language=None)
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if st.button(f"📥 Load this sample", key=title, use_container_width=True):
                    st.session_state['sample_email'] = content
                    st.rerun()

def show_learn_more():
    """Educational content about phishing with enhanced design"""
    st.markdown("### 🎓 Learn About Phishing")
    
    # Introduction
    st.markdown("""
    <div style='background: linear-gradient(135deg, #DBEAFE 0%, #BFDBFE 100%);
                padding: 2rem; border-radius: 12px; margin-bottom: 2rem;
                border-left: 5px solid #3B82F6;'>
        <h4 style='margin-top: 0; color: #1E40AF;'>🎯 What is Phishing?</h4>
        <p style='color: #1E3A8A; margin-bottom: 0;'>
            Phishing is a cybersecurity attack where criminals impersonate legitimate organizations 
            to steal sensitive information like passwords, credit card numbers, or personal data.
            It's the <strong>#1 cause of data breaches</strong> worldwide.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Red flags section
    st.markdown("### 🚩 Common Red Flags")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div style='background: linear-gradient(135deg, #FEE2E2 0%, #FECACA 100%);
                    padding: 1.5rem; border-radius: 12px; height: 100%;
                    border-left: 5px solid #DC2626;'>
            <h4 style='color: #991B1B;'>📝 Content Warning Signs:</h4>
            <ul style='color: #7F1D1D;'>
                <li>Urgent or threatening language</li>
                <li>Requests for passwords/personal info</li>
                <li>Poor grammar and spelling</li>
                <li>Generic greetings ("Dear Customer")</li>
                <li>Too-good-to-be-true offers</li>
                <li>Pressure to act immediately</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div style='background: linear-gradient(135deg, #FFEDD5 0%, #FED7AA 100%);
                    padding: 1.5rem; border-radius: 12px; height: 100%;
                    border-left: 5px solid #EA580C;'>
            <h4 style='color: #9A3412;'>🔧 Technical Indicators:</h4>
            <ul style='color: #7C2D12;'>
                <li>Suspicious sender addresses</li>
                <li>Mismatched URLs (hover to check)</li>
                <li>Unexpected attachments</li>
                <li>Reply-to address differs from sender</li>
                <li>URL shorteners hiding destination</li>
                <li>Misspelled domain names</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Protection tips
    st.markdown("### 🛡️ How to Protect Yourself")
    
    protection_tips = [
        ("🔍", "Verify the Sender", "Check email addresses carefully for subtle misspellings or unusual domains"),
        ("🖱️", "Hover Over Links", "See the real destination before clicking - never trust the display text"),
        ("🔒", "Never Share Passwords", "Legitimate companies will NEVER ask for passwords via email"),
        ("📱", "Enable 2FA", "Add an extra layer of security to all your important accounts"),
        ("📢", "Report Suspicious Emails", "Help protect others by reporting phishing attempts"),
        ("🔄", "Keep Software Updated", "Security patches fix vulnerabilities that attackers exploit"),
        ("🔑", "Use Strong Passwords", "Unique passwords for each account - consider a password manager"),
        ("🧠", "Trust Your Instincts", "If something feels off, it probably is - verify through official channels")
    ]
    
    for emoji, title, description in protection_tips:
        st.markdown(f"""
        <div style='background: linear-gradient(135deg, #F9FAFB 0%, #F3F4F6 100%);
                    padding: 1rem; border-radius: 12px; margin-bottom: 0.8rem;
                    border-left: 5px solid #667eea;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);'>
            <div style='display: flex; align-items: center; gap: 1rem;'>
                <div style='font-size: 2rem;'>{emoji}</div>
                <div style='flex: 1;'>
                    <strong style='color: #1F2937; font-size: 1.1rem;'>{title}</strong><br>
                    <span style='color: #6B7280;'>{description}</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Statistics
    st.markdown("### 📈 Phishing Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    stats = [
        ("90%", "of data breaches", "start with phishing", col1),
        ("1 in 4", "people click", "on phishing links", col2),
        ("$1.8B", "lost annually", "to phishing scams", col3),
        ("400%", "increase during", "COVID-19 pandemic", col4)
    ]
    
    for number, label1, label2, col in stats:
        with col:
            st.markdown(f"""
            <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        padding: 1.5rem; border-radius: 12px; text-align: center; color: white;
                        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);'>
                <div style='font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem;'>{number}</div>
                <div style='font-size: 0.9rem; opacity: 0.9;'>{label1}<br>{label2}</div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("<br><br>", unsafe_allow_html=True)
    
    # Final note
    st.markdown("""
    <div style='background: linear-gradient(135deg, #D1FAE5 0%, #A7F3D0 100%);
                padding: 2rem; border-radius: 12px; text-align: center;
                border: 2px solid #10B981;'>
        <h3 style='color: #065F46; margin-top: 0;'>🎓 Stay Educated, Stay Safe</h3>
        <p style='color: #047857; margin-bottom: 0;'>
            Understanding phishing tactics is your first line of defense. Share this knowledge with 
            friends, family, and colleagues to help create a safer digital environment for everyone.
        </p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()