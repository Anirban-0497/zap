import os
import json
import logging
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, red, orange, yellow, blue, green
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate professional PDF reports from ZAP scan results"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=20,
            spaceAfter=30,
            textColor=colors.darkblue
        ))
        
        # Heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.darkblue
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=12,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=12,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontSize=12,
            spaceAfter=6
        ))
    
    def generate_pdf_report(self, scan_results, target_url):
        """Generate comprehensive PDF report"""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.getcwd(), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'security_report_{timestamp}.pdf'
            filepath = os.path.join(reports_dir, filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            content = []
            
            # Title page
            content.extend(self.build_title_page(scan_results, target_url))
            content.append(PageBreak())
            
            # Executive summary
            content.extend(self.build_executive_summary(scan_results))
            content.append(PageBreak())
            
            # Vulnerability details
            content.extend(self.build_vulnerability_details(scan_results))
            
            # Recommendations
            content.append(PageBreak())
            content.extend(self.build_recommendations(scan_results))
            
            # Build PDF
            doc.build(content)
            
            logger.info(f"PDF report generated: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {str(e)}")
            raise
    
    def build_title_page(self, scan_results, target_url):
        """Build title page content"""
        content = []
        
        # Title
        content.append(Paragraph("Web Security Assessment Report", self.styles['CustomTitle']))
        content.append(Spacer(1, 30))
        
        # Target information
        content.append(Paragraph("Target Information", self.styles['CustomHeading1']))
        
        target_data = [
            ['Target URL:', target_url],
            ['Scan Date:', scan_results.get('scan_timestamp', 'N/A')],
            ['Total Alerts:', str(scan_results.get('alert_count', 0))],
            ['URLs Scanned:', str(scan_results.get('urls_scanned', 0))]
        ]
        
        target_table = Table(target_data, colWidths=[2*inch, 4*inch])
        target_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        content.append(target_table)
        content.append(Spacer(1, 30))
        
        # Risk summary
        content.append(Paragraph("Risk Summary", self.styles['CustomHeading1']))
        
        risk_summary = scan_results.get('risk_summary', {})
        risk_data = [
            ['Risk Level', 'Count'],
            ['High', str(risk_summary.get('High', 0))],
            ['Medium', str(risk_summary.get('Medium', 0))],
            ['Low', str(risk_summary.get('Low', 0))],
            ['Informational', str(risk_summary.get('Informational', 0))]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('TEXTCOLOR', (1, 1), (1, 1), colors.red),  # High risk
            ('TEXTCOLOR', (1, 2), (1, 2), colors.orange),  # Medium risk
            ('TEXTCOLOR', (1, 3), (1, 3), colors.green),  # Low risk
        ]))
        
        content.append(risk_table)
        
        return content
    
    def build_executive_summary(self, scan_results):
        """Build executive summary section"""
        content = []
        
        content.append(Paragraph("Executive Summary", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        # Summary text
        summary_text = self.generate_summary_text(scan_results)
        content.append(Paragraph(summary_text, self.styles['Normal']))
        content.append(Spacer(1, 20))
        
        # Key findings
        content.append(Paragraph("Key Findings", self.styles['CustomHeading1']))
        
        alerts = scan_results.get('alerts', [])
        high_risk_alerts = [alert for alert in alerts if alert.get('risk') == 'High']
        
        if high_risk_alerts:
            content.append(Paragraph("Critical Issues Found:", self.styles['HighRisk']))
            for alert in high_risk_alerts[:5]:  # Show top 5
                content.append(Paragraph(f"• {alert.get('name', 'Unknown')}", self.styles['Normal']))
        else:
            content.append(Paragraph("No critical security issues found.", self.styles['Normal']))
        
        return content
    
    def build_vulnerability_details(self, scan_results):
        """Build detailed vulnerability section"""
        content = []
        
        content.append(Paragraph("Vulnerability Details", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        alerts = scan_results.get('alerts', [])
        
        # Group alerts by risk level
        risk_groups = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }
        
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            if risk in risk_groups:
                risk_groups[risk].append(alert)
        
        # Generate sections for each risk level
        for risk_level, risk_alerts in risk_groups.items():
            if risk_alerts:
                content.append(Paragraph(f"{risk_level} Risk Vulnerabilities", self.styles['CustomHeading1']))
                
                for i, alert in enumerate(risk_alerts):
                    content.extend(self.build_vulnerability_item(alert, i + 1))
                    content.append(Spacer(1, 15))
        
        return content
    
    def build_vulnerability_item(self, alert, index):
        """Build individual vulnerability item"""
        content = []
        
        # Vulnerability name
        vuln_name = f"{index}. {alert.get('name', 'Unknown Vulnerability')}"
        content.append(Paragraph(vuln_name, self.styles['CustomHeading2']))
        
        # Details table
        details = [
            ['Description:', alert.get('description', 'No description available')],
            ['Risk Level:', alert.get('risk', 'Unknown')],
            ['Confidence:', alert.get('confidence', 'Unknown')],
            ['URL:', alert.get('url', 'N/A')],
            ['Parameter:', alert.get('param', 'N/A')]
        ]
        
        details_table = Table(details, colWidths=[1.5*inch, 4.5*inch])
        details_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        content.append(details_table)
        
        # Solution if available
        solution = alert.get('solution', '')
        if solution:
            content.append(Spacer(1, 10))
            content.append(Paragraph("Recommended Solution:", self.styles['Heading3']))
            content.append(Paragraph(solution, self.styles['Normal']))
        
        return content
    
    def build_recommendations(self, scan_results):
        """Build recommendations section"""
        content = []
        
        content.append(Paragraph("Security Recommendations", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        # General recommendations
        general_recommendations = [
            "Implement proper input validation and sanitization",
            "Use HTTPS for all communications",
            "Implement Content Security Policy (CSP) headers",
            "Regular security updates and patches",
            "Implement proper authentication and authorization",
            "Use secure coding practices",
            "Regular security assessments and penetration testing",
            "Implement proper logging and monitoring"
        ]
        
        content.append(Paragraph("General Security Best Practices:", self.styles['CustomHeading1']))
        
        for rec in general_recommendations:
            content.append(Paragraph(f"• {rec}", self.styles['Normal']))
        
        content.append(Spacer(1, 20))
        
        # Specific recommendations based on findings
        alerts = scan_results.get('alerts', [])
        if alerts:
            content.append(Paragraph("Specific Recommendations Based on Findings:", self.styles['CustomHeading1']))
            
            # Get unique vulnerability types
            vuln_types = list(set(alert.get('name', '') for alert in alerts))
            
            for vuln_type in vuln_types[:10]:  # Limit to top 10
                if vuln_type:
                    recommendation = self.get_specific_recommendation(vuln_type)
                    content.append(Paragraph(f"• {recommendation}", self.styles['Normal']))
        
        return content
    
    def generate_summary_text(self, scan_results):
        """Generate executive summary text"""
        alert_count = scan_results.get('alert_count', 0)
        high_risk = scan_results.get('risk_summary', {}).get('High', 0)
        medium_risk = scan_results.get('risk_summary', {}).get('Medium', 0)
        
        if alert_count == 0:
            return "The security assessment completed successfully with no security vulnerabilities identified. The target application appears to follow good security practices."
        
        summary = f"The security assessment identified {alert_count} potential security issues. "
        
        if high_risk > 0:
            summary += f"Among these, {high_risk} are classified as high risk and require immediate attention. "
        
        if medium_risk > 0:
            summary += f"Additionally, {medium_risk} medium-risk vulnerabilities were found that should be addressed in the near term. "
        
        summary += "This report provides detailed information about each finding along with recommended remediation steps."
        
        return summary
    
    def get_specific_recommendation(self, vuln_type):
        """Get specific recommendation for vulnerability type"""
        recommendations = {
            'Cross Site Scripting': 'Implement proper input validation and output encoding',
            'SQL Injection': 'Use parameterized queries and stored procedures',
            'Cross-Site Request Forgery': 'Implement CSRF tokens for state-changing operations',
            'Missing Anti-clickjacking Header': 'Add X-Frame-Options header',
            'Cookie No HttpOnly Flag': 'Set HttpOnly flag on sensitive cookies',
            'Cookie Without Secure Flag': 'Set Secure flag on all cookies over HTTPS',
            'Information Disclosure': 'Remove sensitive information from error messages and headers'
        }
        
        for key, rec in recommendations.items():
            if key.lower() in vuln_type.lower():
                return rec
        
        return f"Address the identified {vuln_type} vulnerability according to security best practices"
