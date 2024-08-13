import requests
import base64
import os
import mimetypes
from typing import List, Dict, Optional

class Attachment:
    def __init__(self, file_path: str):
        self.name = os.path.basename(file_path)
        self.content = self._encode_file(file_path)
        self.content_type = self._guess_mime_type(file_path)

    def _encode_file(self, file_path: str) -> str:
        with open(file_path, "rb") as file:
            return base64.b64encode(file.read()).decode('utf-8')

    def _guess_mime_type(self, file_path: str) -> str:
        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"

    def to_dict(self) -> Dict[str, str]:
        return {
            "Name": self.name,
            "Content": self.content,
            "ContentType": self.content_type
        }

class Email:
    def __init__(self, from_email: str, to: str, subject: str, html_body: str):
        self.from_email = from_email
        self.to = to
        self.subject = subject
        self.html_body = html_body
        self.attachments: List[Attachment] = []

    def add_attachment(self, file_path: str) -> None:
        if os.path.exists(file_path):
            self.attachments.append(Attachment(file_path))
        else:
            raise FileNotFoundError(f"File not found: {file_path}")

    def to_dict(self) -> Dict[str, any]:
        email_dict = {
            "From": self.from_email,
            "To": self.to,
            "Subject": self.subject,
            "HtmlBody": self.html_body
        }
        if self.attachments:
            email_dict["Attachments"] = [attachment.to_dict() for attachment in self.attachments]
        return email_dict

class PostmarkEmailSender:
    BASE_URL = "https://api.postmarkapp.com/email"

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Postmark-Server-Token": self.api_token
        }

    def send(self, email: Email) -> Dict[str, any]:
        try:
            response = requests.post(self.BASE_URL, headers=self.headers, json=email.to_dict())
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"error": str(e)}