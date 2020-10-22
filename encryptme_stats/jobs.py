from multiprocessing import Process, Value
import os
import signal

import vici


class IkeSessionMonitor:
    """
    Monitors IKE up-down events so we can always get session information as
    users disconnect.
    """
    def __init__(self):
        self.push_session_stats = Value('i', 0)
        self.process = Process(
            target=self.run,
            args=[self.push_session_stats],
            name='IPSecSessions',
        )

    def connect(self):
        # wait up to 10 seconds to ensure the socket is available
        tries = 0
        max_tries = 10
        while tries < max_tries:
            try:
                return vici.Session()
            except socket.error as e:
                time.sleep(1)
        raise Exception(f'Failed to connect to Vici socket after {max_tries} tries.')

    def run(self, push_session_stats):
        session = self.connect()
        # we'll block with each loop until the event we care about happens
        for label, event in session.listen(["ike-updown"]):
            # ... just in case!
            if label != "ike-updown":
                continue
            # don't worry about 'up' events; we'll always get this on regular
            # polls or disconnect
            if event.get("up", "") == "yes":
                continue
            # flag ourselves to send session stats
            push_session_stats.value = 1

    def kill(self, sigkill=False):
        if self.process.is_alive():
            if sigkill:
                os.kill(self.process.pid, signal.SIGKILL)
            else:
                self.process.terminate()
