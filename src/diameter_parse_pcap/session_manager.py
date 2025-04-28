from typing import *
from diameter_telecom.subscriber import Subscriber
from diameter_telecom.constants import *
from diameter_telecom.diameter_session import GxSession, SySession, RxSession
from diameter_telecom.diameter_message import DiameterMessage

import logging
logger = logging.getLogger(__name__)

import threading

class SessionManager:
    subscribers: Dict[str, Subscriber]
    gx_sessions: Dict[str, GxSession]
    sy_sessions: Dict[str, SySession]
    rx_sessions: Dict[str, RxSession]
    orphan_messages: List[DiameterMessage]

    def __init__(self,
                 subscribers: dict = None,
                 gx_sessions: dict = None,
                 sy_sessions: dict = None,
                 rx_sessions: dict = None,
                 ): 
        if subscribers:
            self.subscribers = subscribers
        else:
            self.subscribers = {}
        if gx_sessions:
            self.gx_sessions = gx_sessions
        else:
            self.gx_sessions = {}
        if sy_sessions:
            self.sy_sessions = sy_sessions
        else:
            self.sy_sessions = {}
        if rx_sessions:
            self.rx_sessions = rx_sessions
        else:
            self.rx_sessions = {}

        self.lock = threading.Lock()

        self.orphan_messages = []

    def add_orphan_message(self, message):
        with self.lock:
            session_id = message.session_id
            if self.gx_sessions.get_session_by_id(session_id):
                print(f"GX session found for session_id: {session_id}, message: {message}")
            self.orphan_messages.append(message)

    def add_gx_session(self, gx_session: GxSession):
        with self.lock:
            self.gx_sessions[gx_session.session_id] = gx_session

    def add_sy_session(self, sy_session: SySession):
        with self.lock:
            self.sy_sessions[sy_session.session_id] = sy_session

    def add_rx_session(self, rx_session: RxSession):
        with self.lock:
            self.rx_sessions[rx_session.session_id] = rx_session

    def get_gx_session(self, session_id: str) -> GxSession:
        with self.lock:
            return self.gx_sessions.get(session_id)
        
    def get_sy_session(self, session_id: str) -> SySession:
        with self.lock:
            return self.sy_sessions.get(session_id)
        
    def get_rx_session(self, session_id: str) -> RxSession:
        with self.lock:
            return self.rx_sessions.get(session_id)
        
    def get_active_gx_session_by_msisdn(self, msisdn: str) -> GxSession:
        with self.lock:
            for gx_session in self.gx_sessions.values():
                if gx_session.subscriber.msisdn == msisdn:
                    if not gx_session.active:
                        continue
                    return gx_session
            return None
        
    def get_subscriber_by_msisdn(self, msisdn: str) -> Subscriber:
        with self.lock:
            return self.subscribers.get(msisdn)
        
    def add_subscriber(self, subscriber: Subscriber):
        with self.lock:
            self.subscribers[subscriber.msisdn] = subscriber