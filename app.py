#!/usr/bin/env python3

import sys
import signal
import datetime
import time

import logging
import argparse
import configparser

import requests

from webserver import WebServer
from cloudflared import Tunnel
from oauth import OAuth

class ATBridgeApp:
    access_token = None
    refresh_token = None
    access_token_expires = None
    profile = None
    nonce = None

    def __init__(self):
        self.init_args()
        self.init_config()
        self.init_logging()
        self.init_signal()
        self.init_webserver()
        self.init_tunnel()
        self.init_oauth()
    
    def init_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-v', '--verbose', action='store_true')
        
        self.args = parser.parse_args()

    def init_config(self):
        self.config = configparser.ConfigParser()
        self.config.read("app.conf")

        self.url = self.config.get('DEFAULT', 'url')

        self.secrets = configparser.ConfigParser()
        self.secrets.read("app-secrets.conf")

        self.did = self.secrets.get("DEFAULT", "did", fallback=None)

    def save_secrets(self):
        banner = []

        with open("app-secrets.conf", "r") as f:
            for line in f:
                if line.startswith("#") or line.strip() == "":
                    banner.append(line)
                else:
                    break

        with open("app-secrets.conf", "w") as f:
            for line in banner:
                f.write(line)
            
            self.secrets.write(f)

    def init_logging(self):
        self.log = logging.getLogger(__name__)
        level = self.config.get('DEFAULT', 'log_level', fallback='INFO')

        # Override log level with -v
        if self.args.verbose:
            level = 'DEBUG'

        format = self.config.get('DEFAULT', 'log_format', fallback='[%(asctime)s %(levelname)s] %(message)s')

        logging.basicConfig(level=logging.getLevelName(level), format=format)

    def init_signal(self):
        signal.signal(signal.SIGINT, lambda sig, frame: self.shutdown())

    def init_webserver(self):
        self.webserver = WebServer(self)

    def init_tunnel(self):
        self.tunnel = Tunnel(self)      
    
    def init_oauth(self):
        self.oauth = OAuth(self, on_tokens=self.save_tokens)

    def get_client_id(self):
        return f"{self.url}/oauth/metadata.json"

    def save_tokens(self, data):
        self.did = data['sub']

        # Tokens already set in oauth
        self.secrets.set("DEFAULT", "did", self.did)

        self.save_secrets()
    
    def shutdown(self):
        self.log.info("Shutting down...")
        self.running = False
        self.webserver.shutdown()
        self.tunnel.shutdown()

    def get_profile(self):
        endpoint = f'/xrpc/app.bsky.actor.getProfile?actor={self.did}'

        result = self.oauth.xrpc_call(endpoint)
        if result:
            self.profile = result
            self.log.info(f"Profile: {self.profile}")
        else:
            self.profile = "Error"

        return result        
        
    def start(self):
        self.running = True
        self.log.info("APBridge starting...")
        
        self.webserver.start()
        self.tunnel.start()

        self.log.debug("Waiting for webserver and tunnel to start...")
        time.sleep(3)

        self.oauth.start()

        while self.running:
            self.log.debug(f"Tick..")

            if self.profile is None and self.oauth.has_valid_access_token():
                self.get_profile()

            time.sleep(3)
        
        self.log.info("ATBridge completed.")

if __name__ == "__main__":
    app = ATBridgeApp()
    app.start()
