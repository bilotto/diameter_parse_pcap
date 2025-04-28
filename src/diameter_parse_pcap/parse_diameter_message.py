import sys
import os
from typing import *
from diameter.message import dump
from diameter_telecom.constants import *
from diameter_telecom.diameter_message import DiameterMessage
from diameter_telecom.subscriber import Subscriber
from diameter_telecom.diameter_session import GxSession, SySession
from .session_manager import SessionManager
#
from ._parse_functions import *
from .csv_file import CsvFile

import threading

lock = threading.Lock()

import logging
logger = logging.getLogger(__name__)


def write_to_csv(csv_file: CsvFile,
                 diameter_message: DiameterMessage,
                 ):
        try:
            row = {}
            for column in csv_file.get_csv_columns():
                row[column] = getattr(diameter_message, column)
            csv_file.write_row(row)
            csv_file.flush()
        except Exception as e:
            logger.error(f"Error writing to csv file - Error : {e}")
            pass
        

def parse_diameter_message(diameter_message: DiameterMessage,
                             session_manager: SessionManager,
                             create_subscribers: bool = True,
                             csv_file: CsvFile = None,
                             ):
    try:
        subscriber_ = None
        session_id = diameter_message.message.session_id
        gx_session = None
        sy_session = None
        rx_session = None
        framed_ip_address = None
        framed_ipv6_prefix = None
        mcc_mnc = None
        apn = None

        if hasattr(diameter_message.message, 'subscription_id'):
            parsed_subscription_id = parse_subscription_id(diameter_message.message.subscription_id)
            msisdn = parsed_subscription_id[0]
            imsi = parsed_subscription_id[1]
            # Try to check if the subscribers already exists in SessionManager
            subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
            if not subscriber_:
                if not create_subscribers:
                    return None
                session_manager.add_subscriber(Subscriber(msisdn, imsi))
                subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                diameter_message.set_subscriber(subscriber_)
                
                

        if diameter_message.app_id == APP_3GPP_GX:
            # First, try to get the gx_session by session_id
            gx_session = session_manager.get_gx_session(session_id)
            # If gx_session is found, we can retrieve subscriber from GxSession
            if gx_session:
                subscriber_ = gx_session.subscriber
                # If gx_session is found and it's CCR_I, that means it's probably a duplicate CCR_I
                if diameter_message.name == CCR_I:
                    logger.error(f"Session already exists: {gx_session}")
                    return None
            else:
                # Means gx_session not found, ok
                if diameter_message.name != CCR_I:
                    return None
            # If gx_session not found and it's not a CCR_I, we can not identify the subscriber and the diameter_message.subscriber will be None
            # elif not(gx_session) and diameter_message.name != CCR_I:
            #     return diameter_message
            if diameter_message.name == CCR_I:
                # Get some information from the diameter_message that we know for sure it's there
                apn = diameter_message.message.called_station_id
                #
                # If it's a CCR_I, we can identify the subscriber by subscription_id
                parsed_subscription_id = parse_subscription_id(diameter_message.message.subscription_id)
                msisdn = parsed_subscription_id[0]
                imsi = parsed_subscription_id[1]
                # Try to check if the subscribers already exists in SessionManager
                subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                if not subscriber_:
                    # If subscriber not found, we can proceed to create a new subscriber if the flag create_subscribers is True, or discard the message
                    if not create_subscribers:
                        return None
                    session_manager.add_subscriber(Subscriber(msisdn, imsi))
                    subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                # Subscriber found, lets create the GxSession
                #
                if diameter_message.message.framed_ip_address:
                    framed_ip_address = bytes_to_ip(diameter_message.message.framed_ip_address)
                elif diameter_message.message.framed_ipv6_prefix:
                    framed_ipv6_prefix = decode_framed_ipv6(diameter_message.message.framed_ipv6_prefix)
                else:
                    raise Exception(f"Framed-IP-Address not found in {diameter_message.name}: {subscriber_}")
                #
                gx_session = GxSession(session_id)
                gx_session.set_subscriber(subscriber_)
                gx_session.set_apn(apn)
                gx_session.set_framed_ip_address(framed_ip_address)
                gx_session.set_framed_ipv6_prefix(framed_ipv6_prefix)
                if hasattr(diameter_message.message, 'sgsn_mcc_mnc'):
                    mcc_mnc = diameter_message.message.sgsn_mcc_mnc
                gx_session.set_mcc_mnc(mcc_mnc)
                session_manager.add_gx_session(gx_session)
            else:
                # It's CCR_U or CCR_T - GxSession should have been retrieved earlier by session_id
                if not gx_session:
                    logger.error(f"GxSession not found for session_id: {session_id}")
                    return diameter_message
                subscriber_ = gx_session.subscriber
            # Set diameter_message attributes
            diameter_message.set_subscriber(subscriber_)
            diameter_message.set_framed_ip_address(gx_session.framed_ip_address or gx_session.framed_ipv6_prefix)
            diameter_message.set_mcc_mnc(gx_session.mcc_mnc)
            # Finally, add the message to the GxSession
            gx_session.add_message(diameter_message)
            session_manager.add_gx_session(gx_session)
        elif diameter_message.app_id == APP_3GPP_SY:
            sy_session = session_manager.get_sy_session(session_id)
            if not sy_session and not subscriber_:
                return None
            if diameter_message.name == SLR:
            # First, lets get the GxSession associated with the Sy Session
            # SLR session normally has the subscription_id, so the subscriber should be already set
                gx_session = session_manager.get_active_gx_session_by_msisdn(subscriber_.msisdn)
                if not gx_session:
                    logger.error(f"GxSession active not found for msisdn: {subscriber_.msisdn}")
                    return None
                sy_session = SySession(session_id)
                sy_session.set_gx_session_id(gx_session.session_id)
                sy_session.set_subscriber(subscriber_)
                session_manager.add_sy_session(sy_session)
                diameter_message.set_subscriber(subscriber_)
            else:
                subscriber_ = sy_session.subscriber
                diameter_message.set_subscriber(subscriber_)
            

        elif diameter_message.app_id == APP_3GPP_RX:
            pass
        else:
            return None
        try:
            with lock:
                write_to_csv(csv_file, diameter_message)
        except Exception as e:
            logger.error(f"Error writing to csv file - Error : {e}")
            logger.error(dump(diameter_message))
            raise e

        return True
    except Exception as e:
        logger.error(f"Error processing diameter message: {e}")
        logger.error(diameter_message.dump())
        raise e
