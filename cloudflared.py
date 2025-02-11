
import shutil
import subprocess
import threading
import re

class Tunnel:
    def __init__(self, app):
        self.config = app.config
        self.log = app.log
        self.secrets = app.secrets

        self.init()

    def get_tunnel_command(self):
        cloudflared = shutil.which('cloudflared')
        token = self.secrets.get("DEFAULT", "cloudflared_token")
        
        cmd = [
            cloudflared,
            "tunnel",
            "--config",
            "tunnel-config.yml",
            "run",
            "--token",
            token
        ]

        return cmd

    def run_tunnel(self, cmd):
        token = self.secrets.get("DEFAULT", "cloudflared_token")

        while self.running:
            self.log.info(f"Starting cloudflared..")
            
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
                while proc.poll() is None:
                    line = str(proc.stdout.readline(), encoding="utf-8").rstrip("\n")

                    # Prevent accidental reveal of token
                    line = re.sub(token, "[TOKEN]", line)

                    self.log.debug(f"cloudflared: {line}")

            return

    def init(self):
        cmd = self.get_tunnel_command()
        self.tunthread = threading.Thread(target=self.run_tunnel, args=(cmd,))

    def start(self):
        self.running = True
        self.tunthread.start()
    
    def shutdown(self):
        self.running = False
        self.tunthread.join()
        self.log.info("Cloudflared stopped.")
