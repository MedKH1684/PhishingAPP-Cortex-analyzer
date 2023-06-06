#!/usr/bin/env python3
import pyexifinfo
import magic
import os
import json
import tempfile
import zipfile
import requests
from bs4 import BeautifulSoup
from cortexutils.analyzer import Analyzer

class PhishingApp(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.filepath = self.get_param("file", None, "File parameter is missing.")
        self.filename = self.get_param("filename", None, "Filename is missing.")
        self.filetype = pyexifinfo.fileType(self.filepath)
        self.mimetype = magic.Magic(mime=True).from_file(self.filepath)

        self.ip_address = self.get_param("config.ip_address", None, "IP address is missing.")


    def run(self):
        
        results = []

        json_result = requests.post(
            f'http://{self.ip_address}:8000/upload_eml', 
            headers={'accept': 'application/json'}, 
            files={'eml_file': (str(self.filename), open(str(self.filepath), 'rb'), 'message/rfc822')}
        ).json()

        attachement_id = json_result['attachments']

        attachement = requests.get(
            f'http://{self.ip_address}:8000/attachments/{attachement_id}',
            stream=True
        )

        attachements_dir="/opt/attachements"
        with open(f"{attachements_dir}/{attachement_id}", 'wb') as file:
            for chunk in attachement.iter_content(chunk_size=8192):
                file.write(chunk)

        self.report(json_result)

if __name__ == "__main__":
    PhishingApp().run()
