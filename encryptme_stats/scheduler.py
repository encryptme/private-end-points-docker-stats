"""Probe scheduler and sender."""

from functools import partial
from multiprocessing import Process, Queue
import datetime
import json
import logging
import os
import random
import signal
import sys
import time
import traceback
import uuid

import requests
import schedule

from encryptme_stats import metrics
from encryptme_stats import jobs


class Message:
    """A message to send.

    Handles own rescheduling.
    """

    def __init__(self, data, max_retries=0, retry_interval=30, server=None):
        self.data = data
        self.max_retries = max_retries
        self.retry_interval = retry_interval
        self.server = server
        self.rescheduled = False
        self.retries = 0
        self.timeout = 30

    def send(self):
        """Initiate sending of this message."""
        try:
            response = requests.post(
                self.server,
                json=self.data,
                timeout=self.timeout
            )
            if not response.status_code == 200:
                raise Exception('Retry required: %s' % response.status_code)
        except Exception as exc:
            logging.error("Failed to send message: %s", exc)
            self.retry()

    def retry(self):
        """Retry sending until max_retries is hit."""
        if self.retries >= self.max_retries:
            logging.error("Failed to send message: %s", self.data)
            return

        def resend():
            """Scheduler endpoint for resending."""
            logging.warning("Retry %d of %d", self.retries, self.max_retries)
            try:
                response = requests.post(
                    self.server,
                    json=self.data,
                    timeout=self.timeout
                )
                if not response.status_code == '200':
                    raise Exception('Retry required')
                return schedule.CancelJob
            except Exception as exc:
                logging.error("Failed to send message - retrying: %s", exc)

                if self.retries >= self.max_retries:
                    logging.error("Failed to send message (%d retries): %s",
                                  self.retries,
                                  self.data)
                    return schedule.CancelJob

            self.retries += 1
            self.rescheduled = True

        schedule.every(self.retry_interval).seconds.do(resend)


class Scheduler:
    """Singleton that sets up scheduling and starts sending metrics"""

    server_id = None
    server = None
    config = None
    auth_key = None
    ike_session_monitor = None

    @classmethod
    def init(cls, server_info, config, now=False, server=None, auth_key=None):
        """Initialize class attributes."""
        if cls.server:
            raise Exception('The Scheduler has already been initialized.')
        if not server:
            raise Exception("A server URL (e.g. http://pep-stats.example.com) "
                            "is required as a command line parameter or set "
                            "in the encryptme_stats config")

        cls.server = server
        cls.server_info = server_info
        cls.auth_key = auth_key
        cls.config = config
        cls.now = now
        cls.ike_session_monitor = jobs.IkeSessionMonitor()

    @classmethod
    def start(cls):
        """Start the scheduler, and run forever."""
        cls.parse_schedule(cls.config, now=cls.now)
        cls.ike_session_monitor.process.start()

        # ensure that when we stop we also cleanup any child jobs
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, cls.cleanup_and_quit)

        # our primary process handles stats due to be sent based on our config
        # but we have a child process specifically watching for IKE down events
        while True:
            schedule.run_pending()
            # if our session monitoring fails try to reconnect
            if not cls.ike_session_monitor.process.is_alive():
                cls.ike_session_monitor = jobs.IkeSessionMonitor(start=True)
            # check to see if we need to send one-off session stats due to a disconnect
            if cls.ike_session_monitor.push_session_stats.value:
                cls.gather('vpn_session', getattr(metrics, 'vpn_session'))
                cls.ike_session_monitor.push_session_stats.value = 0
            time.sleep(1)

    @classmethod
    def cleanup_and_quit(cls, signal_num=None, frame=None, exception=None):
        """
        Stops all minions, reports any errors, and ends execution.
        """
        # ensure things really end
        cls.ike_session_monitor.kill()
        if signal_num:
            print(f'Aborting; cause signal {signal_num}')
        elif exception:
            frames = []
            tb = traceback.extract_tb(exception.__traceback__)
            for i, frame in enumerate(tb):
                where = frame.name + ' - ' + frame.filename
                frames.append({
                    'line': frame.line,
                    'where': f'{where}:{frame.lineno}',
                    'depth': i,
                })
            print(f"\nAborting; caught exception: {str(exception)}")
            print(json.dumps(frames, indent=4))
        sys.exit(1)


    @classmethod
    def parse_schedule(cls, config, now=False):
        """Parse config to build a schedule."""
        start_offset = random.randint(0, 60)
        if now:
            start_offset = 1

        for method in metrics.__all__:
            interval = float(config[method]['interval'])

            job = schedule.every(interval).seconds.do(
                partial(cls.gather, method, getattr(metrics, method)))

            # Make the next call be sooner
            job.next_run = datetime.datetime.now() + datetime.timedelta(
                seconds=start_offset)

    @classmethod
    def gather(cls, method, metric):
        """Gather statistics from the specified metric callable and send."""
        def make_message(item, retries, interval):
            """Create a Message class."""
            item['@timestamp'] = datetime.datetime.utcnow().isoformat()
            item.update(cls.server_info)
            item['@id'] = str(uuid.uuid4())
            if cls.auth_key:
                item['@auth_key'] = cls.auth_key
            return Message(item, retries, interval, cls.server)

        try:
            result = metric()
            if result:  # don't send empty metrics
                if not isinstance(result, list):
                    result = [result]

                for doc in result:
                    make_message(
                        doc,
                        int(cls.config[method]['max_retries']),
                        int(cls.config[method]['retry_interval'])).send()
        except Exception as exc:
            logging.exception("Failed to gather data: %s", exc)
