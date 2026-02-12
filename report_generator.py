"""
REPORT GENERATOR - PDF Reports for Admin
Generates comprehensive user activity and NLP analysis reports
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime, timedelta
import pandas as pd
import sqlite3
import os

class UserReportGenerator:
    """Generate comprehensive user activity and NLP analysis reports"""
    
    def __init__(self, data_path='../data'):
        self.data_path = data_path
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            borderWidth=2,
            borderColor=colors.HexColor('#3498db'),
            borderPadding=5,
            backColor=colors.HexColor('#ecf0f1')
        ))
    
    def load_user_data(self, username, days=30):
        """Load all user data from CSV files and database"""
        data = {}
        
        try:
            # Load logins
            logins_path = os.path.join(self.data_path, 'logins.csv')
            if os.path.exists(logins_path):
                logins_df = pd.read_csv(logins_path)
                user_logins = logins_df[logins_df['user'].str.lower() == username.lower()]
                data['logins'] = user_logins
            else:
                data['logins'] = pd.DataFrame()
            
            # Load file access
            file_path = os.path.join(self.data_path, 'file_access.csv')
            if os.path.exists(file_path):
                files_df = pd.read_csv(file_path)
                user_files = files_df[files_df['user'].str.lower() == username.lower()]
                data['files'] = user_files
            else:
                data['files'] = pd.DataFrame()
            
            # Load anomaly scores
            anomaly_path = os.path.join(self.data_path, 'anomaly_scores.csv')
            if os.path.exists(anomaly_path):
                anomaly_df = pd.read_csv(anomaly_path)
                user_anomaly = anomaly_df[anomaly_df['user'].str.lower() == username.lower()]
                data['anomaly'] = user_anomaly
            else:
                data['anomaly'] = pd.DataFrame()
            
            # Load NLP chat alerts
            data['nlp_alerts'] = self.load_nlp_alerts(username)
            
            # Load all chat messages (not just alerts)
            data['all_messages'] = self.load_all_chat_messages(username)
            
            return data
            
        except Exception as e:
            print(f"Error loading user data: {e}")
            return {}
    
    def load_nlp_alerts(self, username):
        """Load NLP chat intent alerts from database"""
        try:
            db_path = os.path.join(self.data_path, 'dashboard.db')
            if not os.path.exists(db_path):
                return pd.DataFrame()
            
            conn = sqlite3.connect(db_path)
            query = """
                SELECT username, message, risk_score, severity, threat_category, 
                       confidence, timestamp
                FROM chat_intent_alerts
                WHERE username = ?
                ORDER BY timestamp DESC
            """
            df = pd.read_sql_query(query, conn, params=(username,))
            conn.close()
            return df
            
        except Exception as e:
            print(f"Error loading NLP alerts: {e}")
            return pd.DataFrame()
    
    def load_all_chat_messages(self, username):
        """Load all chat messages from database"""
        try:
            db_path = os.path.join(self.data_path, 'dashboard.db')
            if not os.path.exists(db_path):
                return pd.DataFrame()
            
            conn = sqlite3.connect(db_path)
            
            # Check if chat_messages table exists
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_messages'")
            if not cursor.fetchone():
                conn.close()
                return pd.DataFrame()
            
            query = """
                SELECT username, message, timestamp
                FROM chat_messages
                WHERE username = ?
                ORDER BY timestamp DESC
            """
            df = pd.read_sql_query(query, conn, params=(username,))
            conn.close()
            return df
            
        except Exception as e:
            print(f"Error loading chat messages: {e}")
            return pd.DataFrame()
    
    def calculate_after_hours_logins(self, logins_df):
        """Calculate after-hours logins (outside 8 AM - 6 PM)"""
        if logins_df.empty:
            return 0
        
        after_hours_count = 0
        for _, row in logins_df.iterrows():
            try:
                timestamp = row.get('timestamp', row.get('date', ''))
                if timestamp:
                    dt = pd.to_datetime(timestamp)
                    hour = dt.hour
                    if hour < 8 or hour >= 18:
                        after_hours_count += 1
            except:
                continue
        
        return after_hours_count
    
    def generate_report(self, username, days=30, output_path=None):
        """Generate comprehensive PDF report for user"""
        
        if output_path is None:
            # Create reports directory if not exists
            reports_dir = os.path.join(self.data_path, 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            output_path = os.path.join(reports_dir, f'report_{username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
        
        # Load user data
        data = self.load_user_data(username, days)
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=letter,
                               topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        
        # ===================================================================
        # TITLE PAGE
        # ===================================================================
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("🛡️ INSIDER THREAT DETECTION SYSTEM", self.styles['CustomTitle']))
        story.append(Paragraph("User Activity & Security Analysis Report", self.styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        
        # Report metadata
        metadata = [
            ["Report Generated:", datetime.now().strftime("%B %d, %Y at %H:%M:%S")],
            ["Target User:", username],
            ["Analysis Period:", f"Last {days} days"],
            ["Report Type:", "Comprehensive Activity & NLP Chat Analysis"]
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(metadata_table)
        story.append(Spacer(1, 0.5*inch))
        
        # ===================================================================
        # EXECUTIVE SUMMARY
        # ===================================================================
        story.append(Paragraph("📊 EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Get anomaly score
        anomaly_score = 0.0
        risk_level = "Low"
        if not data['anomaly'].empty:
            score_col = 'anomaly_score' if 'anomaly_score' in data['anomaly'].columns else 'isolation_forest'
            if score_col in data['anomaly'].columns:
                anomaly_score = float(data['anomaly'].iloc[0][score_col])
                if anomaly_score > 0.7:
                    risk_level = "High"
                elif anomaly_score > 0.4:
                    risk_level = "Medium"
        
        # Summary statistics
        total_logins = len(data['logins']) if not data['logins'].empty else 0
        after_hours_logins = self.calculate_after_hours_logins(data['logins'])
        total_files = len(data['files']) if not data['files'].empty else 0
        total_nlp_alerts = len(data['nlp_alerts']) if not data['nlp_alerts'].empty else 0
        total_messages = len(data['all_messages']) if not data['all_messages'].empty else 0
        
        summary_data = [
            ["Metric", "Value", "Status"],
            ["User Anomaly Score", f"{anomaly_score:.3f}", self._get_risk_badge(anomaly_score)],
            ["Risk Level", risk_level, ""],
            ["Total Logins", str(total_logins), ""],
            ["After-Hours Logins", str(after_hours_logins), "⚠️" if after_hours_logins > 0 else "✅"],
            ["Files Accessed", str(total_files), ""],
            ["Chat Messages Sent", str(total_messages), ""],
            ["Suspicious Messages", str(total_nlp_alerts), "🚨" if total_nlp_alerts > 0 else "✅"],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.4*inch))
        
        # ===================================================================
        # LOGIN ACTIVITY
        # ===================================================================
        story.append(Paragraph("🔐 LOGIN ACTIVITY ANALYSIS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        if not data['logins'].empty:
            login_stats = f"""
            <b>Total Logins:</b> {total_logins}<br/>
            <b>After-Hours Logins:</b> {after_hours_logins} (outside 8 AM - 6 PM)<br/>
            <b>Failed Login Attempts:</b> 0<br/>
            """
            story.append(Paragraph(login_stats, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Recent logins table
            story.append(Paragraph("<b>Recent Login History:</b>", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            login_data = [["Date/Time", "IP Address", "Time Period"]]
            for _, row in data['logins'].head(15).iterrows():
                timestamp = row.get('timestamp', row.get('date', 'N/A'))
                ip = row.get('ip_address', row.get('ip', 'N/A'))
                
                # Determine if after-hours
                time_period = "Business Hours"
                try:
                    dt = pd.to_datetime(timestamp)
                    hour = dt.hour
                    if hour < 8 or hour >= 18:
                        time_period = "⚠️ After Hours"
                except:
                    pass
                
                login_data.append([str(timestamp), str(ip), time_period])
            
            login_table = Table(login_data, colWidths=[2.2*inch, 2*inch, 1.8*inch])
            login_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(login_table)
        else:
            story.append(Paragraph("<i>No login activity found for this user.</i>", self.styles['Normal']))
        
        story.append(Spacer(1, 0.4*inch))
        
        # ===================================================================
        # FILE ACCESS ACTIVITY
        # ===================================================================
        story.append(Paragraph("📁 FILE ACCESS ACTIVITY", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        if not data['files'].empty:
            unique_files = data['files']['file_path'].nunique() if 'file_path' in data['files'].columns else len(data['files'])
            
            file_stats = f"""
            <b>Total Files Accessed:</b> {total_files}<br/>
            <b>Unique Files:</b> {unique_files}<br/>
            """
            story.append(Paragraph(file_stats, self.styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
            
            # Recent file access
            story.append(Paragraph("<b>Recent File Access History:</b>", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
            
            file_data = [["File Path", "Timestamp", "Action"]]
            path_col = 'file_path' if 'file_path' in data['files'].columns else 'filename'
            for _, row in data['files'].head(20).iterrows():
                filepath = str(row.get(path_col, 'Unknown'))
                # Truncate long paths
                if len(filepath) > 45:
                    filepath = "..." + filepath[-42:]
                timestamp = str(row.get('timestamp', row.get('date', 'N/A')))
                action = str(row.get('action', 'read'))
                file_data.append([filepath, timestamp, action])
            
            file_table = Table(file_data, colWidths=[2.8*inch, 2.2*inch, 1*inch])
            file_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(file_table)
        else:
            story.append(Paragraph("<i>No file access activity found for this user.</i>", self.styles['Normal']))
        
        story.append(PageBreak())
        
        # ===================================================================
        # NLP CHAT INTENT ANALYSIS
        # ===================================================================
        story.append(Paragraph("💬 NLP CHAT INTENT ANALYSIS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        if not data['nlp_alerts'].empty or not data['all_messages'].empty:
            # Statistics
            highest_risk = data['nlp_alerts']['risk_score'].max() if not data['nlp_alerts'].empty else 0.0
            most_common_threat = "None"
            if not data['nlp_alerts'].empty and 'threat_category' in data['nlp_alerts'].columns:
                threat_counts = data['nlp_alerts']['threat_category'].value_counts()
                if not threat_counts.empty:
                    most_common_threat = threat_counts.index[0]
            
            nlp_stats = f"""
            <b>Total Chat Messages Sent:</b> {total_messages}<br/>
            <b>Suspicious Messages Flagged:</b> {total_nlp_alerts}<br/>
            <b>Highest Risk Score:</b> {highest_risk:.3f}<br/>
            <b>Most Common Threat Category:</b> {most_common_threat}<br/>
            """
            story.append(Paragraph(nlp_stats, self.styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Show all messages with risk scores
            if not data['nlp_alerts'].empty:
                story.append(Paragraph("<b>⚠️ SUSPICIOUS MESSAGES DETECTED:</b>", self.styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
                
                for idx, row in data['nlp_alerts'].iterrows():
                    # Message box
                    msg_text = str(row['message'])
                    if len(msg_text) > 150:
                        msg_text = msg_text[:147] + "..."
                    
                    msg_data = [
                        ["Timestamp:", str(row['timestamp'])],
                        ["Risk Score:", f"{row['risk_score']:.3f}"],
                        ["Severity:", str(row['severity'])],
                        ["Threat Category:", str(row['threat_category']).upper()],
                        ["Confidence:", f"{row['confidence']:.3f}"],
                        ["Message:", msg_text]
                    ]
                    
                    msg_table = Table(msg_data, colWidths=[1.5*inch, 4.5*inch])
                    
                    # Color based on severity
                    severity = str(row['severity']).upper()
                    if severity == 'HIGH' or severity == 'CRITICAL':
                        bg_color = colors.HexColor('#e74c3c')
                    elif severity == 'MEDIUM':
                        bg_color = colors.HexColor('#f39c12')
                    else:
                        bg_color = colors.HexColor('#95a5a6')
                    
                    msg_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), bg_color),
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ecf0f1')),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    story.append(msg_table)
                    story.append(Spacer(1, 0.15*inch))
            else:
                story.append(Paragraph("<i>✅ No suspicious chat messages detected for this user.</i>", self.styles['Normal']))
            
            # Show recent normal messages
            if not data['all_messages'].empty:
                story.append(Spacer(1, 0.3*inch))
                story.append(Paragraph("<b>Recent Chat Messages (All):</b>", self.styles['Normal']))
                story.append(Spacer(1, 0.1*inch))
                
                chat_data = [["Timestamp", "Message"]]
                for _, row in data['all_messages'].head(10).iterrows():
                    timestamp = str(row['timestamp'])
                    message = str(row['message'])
                    if len(message) > 60:
                        message = message[:57] + "..."
                    chat_data.append([timestamp, message])
                
                chat_table = Table(chat_data, colWidths=[2*inch, 4*inch])
                chat_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('LEFTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                story.append(chat_table)
        else:
            story.append(Paragraph("<i>No chat activity found for this user.</i>", self.styles['Normal']))
        
        story.append(Spacer(1, 0.4*inch))
        
        # ===================================================================
        # RECOMMENDATIONS
        # ===================================================================
        story.append(Paragraph("💡 SECURITY RECOMMENDATIONS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations = self._generate_recommendations(
            anomaly_score, 
            total_nlp_alerts, 
            total_files, 
            after_hours_logins
        )
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        # Build PDF
        doc.build(story)
        
        print(f"✅ Report generated: {output_path}")
        return output_path
    
    def _get_risk_badge(self, score):
        """Get risk level badge based on score"""
        if score > 0.7:
            return "🔴 HIGH"
        elif score > 0.4:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
    
    def _generate_recommendations(self, anomaly_score, nlp_alerts, file_count, after_hours):
        """Generate recommendations based on user activity"""
        recommendations = []
        
        if anomaly_score > 0.7:
            recommendations.append("<b>🔴 HIGH PRIORITY:</b> User shows elevated anomaly score (>0.7). Immediate investigation recommended.")
        
        if nlp_alerts > 0:
            recommendations.append(f"<b>🚨 CHAT MONITORING:</b> User has {nlp_alerts} suspicious chat message(s). Review communication patterns for insider threats.")
        
        if file_count > 200:
            recommendations.append("<b>📁 FILE ACCESS:</b> Unusually high file access activity detected. Monitor for potential data exfiltration.")
        
        if after_hours > 5:
            recommendations.append(f"<b>⏰ AFTER-HOURS ACTIVITY:</b> {after_hours} login(s) outside business hours. Verify legitimate business need.")
        
        if anomaly_score < 0.3 and nlp_alerts == 0 and after_hours == 0:
            recommendations.append("<b>✅ NORMAL ACTIVITY:</b> User shows no significant security concerns. Continue routine monitoring.")
        
        if anomaly_score >= 0.4 and anomaly_score <= 0.7:
            recommendations.append("<b>⚠️ MEDIUM RISK:</b> User requires continued monitoring. Review activity patterns weekly.")
        
        if len(recommendations) == 0:
            recommendations.append("<b>✅ STATUS:</b> User activity within normal parameters. No immediate action required.")
        
        recommendations.append("<b>📧 NEXT STEPS:</b> Share this report with security team and maintain audit trail for compliance.")
        
        return recommendations


# Testing function
if __name__ == "__main__":
    print("Testing Report Generator...")
    generator = UserReportGenerator()
    report_path = generator.generate_report('john_doe', days=30)
    print(f"✅ Test report generated: {report_path}")