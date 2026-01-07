# cloudkraken_v2.1.py - CloudKraken v2.1
# AI-Powered Multi-Cloud CSPM with Auto-Remediation & Compliance Reports
# January 2026 - Built by Grok & You 🐙

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import streamlit as st
from datetime import datetime
import json
import os

# For PDF reports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

st.set_page_config(page_title="CloudKraken v2.1", page_icon="🐙", layout="wide")

class CloudKraken:
    def __init__(self):
        self.findings = []
        self.remediation_log = []
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # === AWS Scan Example (Expand with Azure/GCP later) ===
    def aws_scan(self):
        try:
            session = boto3.Session()
            s3 = session.client('s3')
            ec2 = session.client('ec2')
            iam = session.client('iam')

            st.info("🔍 Scanning AWS...")

            # Public S3 Buckets
            buckets = s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                name = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    grants = acl['Grants']
                    if any(g['Grantee'].get('URI', '').endswith('AllUsers') for g in grants):
                        self.findings.append({
                            "Cloud": "AWS",
                            "Risk": "CRITICAL",
                            "Title": "Public S3 Bucket",
                            "Resource": name,
                            "Details": "Bucket is publicly readable",
                            "CIS": "CIS AWS Foundations 2.1.1",
                            "Remediation": f"Make private: aws s3api put-bucket-acl --bucket {name} --acl private"
                        })
                except: pass

            # Open Security Groups (port 22/3389 to world)
            sgs = ec2.describe_security_groups()['SecurityGroups']
            for sg in sgs:
                for perm in sg['IpPermissions']:
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in perm.get('IpRanges', [])):
                        ports = perm.get('FromPort')
                        if ports in [22, 3389]:
                            self.findings.append({
                                "Cloud": "AWS",
                                "Risk": "HIGH",
                                "Title": f"Security Group Open on Port {ports}",
                                "Resource": sg['GroupId'],
                                "Details": "Ingress from 0.0.0.0/0",
                                "CIS": "CIS AWS Foundations 1.3",
                                "Remediation": f"Revoke public access on {sg['GroupId']}"
                            })

            # Root MFA
            summary = iam.get_account_summary()['SummaryMap']
            if not summary.get('AccountMFAEnabled'):
                self.findings.append({
                    "Cloud": "AWS",
                    "Risk": "CRITICAL",
                    "Title": "Root Account MFA Not Enabled",
                    "Resource": "Root",
                    "CIS": "CIS AWS Foundations 1.4",
                    "Remediation": "Enable MFA for root user in AWS Console"
                })

        except NoCredentialsError:
            st.error("❌ AWS credentials not configured")
        except Exception as e:
            st.error(f"AWS scan error: {e}")

    # === Auto-Remediation ===
    def auto_remediate(self, finding_index, execute=False):
        f = self.findings[finding_index]
        if "Public S3" in f["Title"]:
            bucket = f["Resource"]
            if execute:
                try:
                    s3 = boto3.client('s3')
                    s3.put_bucket_acl(Bucket=bucket, ACL='private')
                    log_entry = f"✅ FIXED: Made {bucket} private"
                    self.remediation_log.append(log_entry)
                    f["Status"] = "Remediated"
                    st.success(log_entry)
                except Exception as e:
                    st.error(f"Fix failed: {e}")
            else:
                st.code(f["Remediation"])
                st.warning("This is a preview. Click 'Execute Fix' to apply.")

    # === Generate PDF Compliance Report ===
    def generate_pdf_report(self):
        filename = f"CloudKraken_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name='TitleBlue', fontSize=24, textColor=colors.HexColor('#64ffda')))
        styles.add(ParagraphStyle(name='Header', fontSize=14, textColor=colors.HexColor('#64ffda')))

        story = []
        story.append(Paragraph("CloudKraken Security Report", styles['TitleBlue']))
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(f"Generated: {self.timestamp}", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))

        # Summary
        critical = len([f for f in self.findings if f["Risk"] == "CRITICAL"])
        high = len([f for f in self.findings if f["Risk"] == "HIGH"])
        story.append(Paragraph("Executive Summary", styles['Header']))
        story.append(Paragraph(f"<b>{critical}</b> CRITICAL • <b>{high}</b> HIGH findings detected", styles['Normal']))
        story.append(Spacer(1, 0.4*inch))

        # Findings Table
        data = [["#", "Cloud", "Risk", "Title", "Resource", "CIS Benchmark", "Status"]]
        for i, f in enumerate(self.findings):
            status = f.get("Status", "Open")
            risk_color = "red" if f["Risk"] == "CRITICAL" else "orange"
            data.append([i+1, f["Cloud"], f["Risk"], f["Title"], f["Resource"], f.get("CIS", "N/A"), status])

        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0a192f')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#112240')),
        ]))
        story.append(table)

        doc.build(story)
        return filename

    def run_scan(self):
        self.aws_scan()  # Add azure_scan(), gcp_scan() later

# === Streamlit Dashboard ===
st.title("🐙 CloudKraken v2.1")
st.markdown("**AI-Powered Multi-Cloud Security Posture Management**")

kraken = CloudKraken()

if st.button("🚀 Run Full Scan", type="primary"):
    with st.spinner("Scanning clouds..."):
        kraken.run_scan()
    st.success(f"Scan complete! Found {len(kraken.findings)} issues.")

if kraken.findings:
    st.header("🔴 Findings & Auto-Remediation")

    for i, f in enumerate(kraken.findings):
        risk_color = "🔴" if f["Risk"] == "CRITICAL" else "🟠"
        with st.expander(f"{risk_color} {f['Risk']} — {f['Title']} ({f['Resource']}) • {f.get('CIS', 'N/A')}"):
            st.write(f"**Details**: {f['Details']}")
            st.code(f["Remediation"], language="bash")

            col1, col2 = st.columns(2)
            with col1:
                if st.button("Execute Fix", key=f"fix_{i}", type="secondary"):
                    if st.checkbox("I confirm this fix is safe to apply", key=f"confirm_{i}"):
                        kraken.auto_remediate(i, execute=True)

            st.write(f"**CIS Benchmark**: {f.get('CIS', 'Not mapped')}")

    st.header("📄 Export Compliance Report")
    if st.button("Generate PDF Report"):
        with st.spinner("Building report..."):
            pdf_file = kraken.generate_pdf_report()
        with open(pdf_file, "rb") as f:
            st.download_button("📥 Download Report", f, file_name=pdf_file, mime="application/pdf")
        st.success("Report ready!")

    if kraken.remediation_log:
        st.header("✅ Remediation Log")
        for log in kraken.remediation_log:
            st.success(log)

else:
    st.info("No scan run yet. Click 'Run Full Scan' to begin.")

st.caption("CloudKraken v2.1 • Open Source • January 2026 🐙")
