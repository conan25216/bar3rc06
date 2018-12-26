#!/usr/bin/env python

import ujson as json
import logging
import zmq
import cif.hunter
from cifsdk.client.zeromq import ZMQ as Client
from cif.constants import HUNTER_ADDR, ROUTER_ADDR, HUNTER_SINK_ADDR
from csirtg_indicator import Indicator
from csirtg_indicator.exceptions import InvalidIndicator
import multiprocessing
import os

logger = logging.getLogger(__name__)

SNDTIMEO = 15000
ZMQ_HWM = 1000000
EXCLUDE = os.environ.get('CIF_HUNTER_EXCLUDE', None)
HUNTER_ADVANCED = os.getenv('CIF_HUNTER_ADVANCED', 0)

TRACE = os.environ.get('CIF_HUNTER_TRACE', False)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

if TRACE in [1, '1']:
   logger.setLevel(logging.DEBUG)


class Hunter(multiprocessing.Process):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        return self

    def __init__(self, remote=HUNTER_ADDR, router=ROUTER_ADDR, token=None):
        multiprocessing.Process.__init__(self)
        self.hunters = remote # hunter recieve desc addr
        self.router = HUNTER_SINK_ADDR # hunter send desc addr
        self.token = token
        self.exit = multiprocessing.Event()
        self.exclude = {}

        if EXCLUDE: # whitelist for hunter provider and tags
            for e in EXCLUDE.split(','): # usage: [cloud_sec_team: malware, 360:dga, ...] 
                provider, tag = e.split(':')

                if not self.exclude.get(provider):
                    self.exclude[provider] = set() # self.exclude = {cloud_sec_team: set()}

                logger.debug('setting hunter to skip: {}/{}'.format(provider, tag))
                self.exclude[provider].add(tag) # skip some exclude providers/tags;

    def _load_plugins(self): # load plugins very clearly said here
        import pkgutil
        logger.debug('loading plugins...')
        plugins = []
        for loader, modname, is_pkg in pkgutil.iter_modules(cif.hunter.__path__, 'cif.hunter.'):
            p = loader.find_module(modname).load_module(modname)
            plugins.append(p.Plugin())
            logger.debug('plugin loaded: {}'.format(modname))

        return plugins

    def terminate(self):
        self.exit.set()

    def start(self):
        router = Client(remote=self.router, token=self.token, nowait=True)
        plugins = self._load_plugins()
        socket = zmq.Context().socket(zmq.PULL) # set a socket to get indicator for hunter later

        socket.SNDTIMEO = SNDTIMEO
        socket.set_hwm(ZMQ_HWM)

        logger.debug('connecting to {}'.format(self.hunters)) # 
        socket.connect(self.hunters)
        logger.debug('starting hunter')

        poller = zmq.Poller() # for polling
        poller.register(socket, zmq.POLLIN)

        while not self.exit.is_set():
            try:
                s = dict(poller.poll(1000)) # after 1 seconds ,break and continune
            except SystemExit or KeyboardInterrupt:
                break

            if socket not in s:
                continue

            data = socket.recv_multipart() # socket is a pull, so self.hunter should be a router? or dealer?

            logger.debug("hunter recieve data from zmq:{}".format(data)) # data: ['{"nolog": "False", "indicator": "10.10.10.10", "limit": "500"}']
            data = json.loads(data[0])

            if isinstance(data, dict):
                if not data.get('indicator'):
                    continue

                if not data.get('itype'):
                    try: # search created by hunter
                        data = Indicator( # from package csirtg_indicators 
                            indicator=data['indicator'],
                            tags='search',
                            confidence=10,
                            group='everyone',
                            tlp='amber',
                        ).__dict__()
                    except InvalidIndicator:
                        logger.debug('skipping invalid indicator: {}'.format(data['indicator']))
                        continue

                if not data.get('tags'):
                    data['tags'] = []

                data = [data]

            for d in data: # first have a search records then go hunter
                d = Indicator(**d)

                if d.indicator in ["", 'localhost', 'example.com']: 
                    continue

                if self.exclude.get(d.provider):
                    for t in d.tags:
                        if t in self.exclude[d.provider]:
                            logger.debug('skipping: {}'.format(d.indicator))

                for p in plugins: # 
                    if p.is_advanced: #  if hunter plugin set to be advanced and hunter advanced is not set.. pass it
                        if not HUNTER_ADVANCED:
                            continue
                    try:
                        p.process(d, router) # run specific hunter plugin, if hunter failed giving up 
                    except Exception as e:
                        logger.error(e)
                        logger.error('[{}] giving up on: {}'.format(p, d)) 
