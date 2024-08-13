import markdown
import os
from weasyprint import HTML, CSS
from dotenv import load_dotenv
from lib.mail import PostmarkEmailSender, Email

class Report:
    def __init__(self):
        load_dotenv() 
        self.api_token = os.getenv('POSTMARK_API_TOKEN')
        self.from_email = os.getenv('FROM_EMAIL')
        self.recipient = os.getenv('RECIPIENT_EMAIL')
        self.sender = PostmarkEmailSender(self.api_token)

    def markdown_to_pdf(self, markdown_text: str):
        output_pdf = "report.pdf"
        # Convert Markdown to HTML, including table support
        html = markdown.markdown(markdown_text, extensions=['tables'])

        # Wrap the converted HTML in a full HTML structure
        full_html = f'''
        <html>
        <body>
        {html}
        </body>
        </html>
        '''

        # CSS for styling, page setup, and table handling with consistent background color
        css = CSS(string='''
            @page {
                size: A4;
                margin: 1cm;
                background-color: #fdf6e3;
            }
            html, body {
                background-color: #fdf6e3;
            }
            body {
                font-family: 'Roboto', Arial, sans-serif;
                font-size: 11pt;
                line-height: 1.6;
                color: #657b83;
            }
            h1, h2, h3, h4, h5, h6 {
                color: #b58900;
                page-break-after: avoid;
            }
            a {
                color: #268bd2;
            }
            code {
                background-color: #eee8d5;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: 'Roboto Mono', monospace;
            }
            pre {
                background-color: #eee8d5;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                font-family: 'Roboto Mono', monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                page-break-inside: auto;
                margin-bottom: 1em;
            }
            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }
            th {
                background-color: #586e75;
                color: #fdf6e3;
                font-weight: bold;
                border: 1px solid #93a1a1;
                padding: 8px;
                text-align: left;
            }
            td {
                background-color: #fdf6e3;
                border: 1px solid #93a1a1;
                padding: 8px;
                text-align: left;
            }
            blockquote {
                border-left: 4px solid #93a1a1;
                padding-left: 15px;
                color: #93a1a1;
            }
            p {
                orphans: 3;
                widows: 3;
            }
        ''')

        # Generate PDF
        HTML(string=full_html).write_pdf(output_pdf, stylesheets=[css])
    
    def send(self, subject="OPIVM - Vulnerability Report", attachment_path="./report.pdf"):
        print("[+] Sending report via PostMark...")
        email = Email(
            from_email=self.from_email,
            to=self.recipient,
            subject=subject,
            html_body="""Dear Infosec,<br>
            Here I attach the vulnerability report.
            """
        )

        try:
            email.add_attachment(attachment_path)
        except FileNotFoundError as e:
            print(f"Error adding attachment: {e}")
            return None

        result = self.sender.send(email)
        return result