#!/usr/bin/env python3

import argparse
import configparser
import json
import time
import logging

class TypicalApp:
    def __init__(self):
        self.init_args()
        self.init_config()
        self.init_logging()
    
    def init_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-v', '--verbose', action='store_true')
        parser.add_argument('-n', '--number', action='store', type=int,
                            help='Specify a numeric argument')
        parser.add_argument('-l', '--load-file', action='store', type=argparse.FileType(),
                            help='Load data from a file')
        parser.add_argument('-u', '--user-id', action='store')
        
        self.args = parser.parse_args()

    def init_config(self):
        self.config = configparser.ConfigParser()
        self.config.read("app.conf")

        self.secrets = configparser.ConfigParser()
        self.secrets.read("app-secrets.conf")

        data = self.config.get('DEFAULT', 'json_data')
        self.json_data = json.loads(data)

    def init_logging(self):
        self.log = logging.getLogger(__name__)
        level = self.config.get('DEFAULT', 'log_level', fallback='INFO')

        # Override log level with -v
        if self.args.verbose:
            level = 'DEBUG'

        format = self.config.get('DEFAULT', 'log_format', fallback='[%(asctime)s %(levelname)s] %(message)s')

        logging.basicConfig(level=logging.getLevelName(level), format=format)

    def start(self):
        self.log.info("TypicalApp starting...")
        
        for i in range(3):
            self.log.debug(f"Tick {i}..")
            time.sleep(1)
        
        self.log.info("TypicalApp completed.")

if __name__ == "__main__":
    app = TypicalApp()
    app.start()
