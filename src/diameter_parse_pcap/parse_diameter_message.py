import sys
import os
from typing import *
from diameter.message import dump
from diameter_telecom.diameter.constants import *
from diameter_telecom.diameter.parse_avp import *
from diameter_telecom import DiameterMessage, Subscriber
from diameter_telecom.diameter.session import *
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
                value = getattr(diameter_message, column)
                # Convert value to string and handle None values
                if value is None:
                    row[column] = ""
                else:
                    row[column] = str(value).strip()
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

        # if hasattr(diameter_message.message, 'subscription_id'):
        #     parsed_subscription_id = parse_subscription_id(diameter_message.message.subscription_id)
        #     msisdn = parsed_subscription_id[0]
        #     imsi = parsed_subscription_id[1]
        #     # Try to check if the subscribers already exists in SessionManager
        #     subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
        #     if not subscriber_:
        #         if not create_subscribers:
        #             return None
        #         session_manager.add_subscriber(Subscriber(msisdn, imsi))
        #         subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
        #         logger.info(f"Added subscriber: {subscriber_} in message: {diameter_message.name}")
        #         diameter_message.subscriber = subscriber_
                
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
                called_station_id = diameter_message.message.called_station_id
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
                    session_manager.add_subscriber(Subscriber(msisdn, msisdn, imsi))
                    subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                if diameter_message.message.framed_ip_address:
                    framed_ip_address = bytes_to_ip(diameter_message.message.framed_ip_address)
                if diameter_message.message.framed_ipv6_prefix:
                    framed_ipv6_prefix = decode_framed_ipv6(diameter_message.message.framed_ipv6_prefix)
                gx_session = GxSession(session_id, subscriber=subscriber_)
                # gx_session.set_subscriber(subscriber_)
                if hasattr(diameter_message.message, 'sgsn_mcc_mnc'):
                    gx_session.sgsn_mcc_mnc = diameter_message.message.sgsn_mcc_mnc
                gx_session.framed_ipv6_prefix = framed_ipv6_prefix
                gx_session.framed_ip_address = framed_ip_address
                gx_session.called_station_id = called_station_id
                session_manager.add_gx_session(gx_session)
            else:
                # It's CCR_U or CCR_T - GxSession should have been retrieved earlier by session_id
                if not gx_session:
                    logger.error(f"GxSession not found for session_id: {session_id}")
                    return diameter_message
                subscriber_ = gx_session.subscriber
            # Set diameter_message attributes
            diameter_message.subscriber = subscriber_
            diameter_message.framed_ip_address = gx_session.framed_ip_address
            diameter_message.framed_ipv6_prefix = gx_session.framed_ipv6_prefix
            diameter_message.sgsn_mcc_mnc = gx_session.sgsn_mcc_mnc
            diameter_message.called_station_id = gx_session.called_station_id
            # Finally, add the message to the GxSession
            gx_session.add_message(diameter_message)
            session_manager.add_gx_session(gx_session)
        elif diameter_message.app_id == APP_3GPP_SY:
            sy_session = session_manager.get_sy_session(session_id)
            if not sy_session:
                if diameter_message.name != SLR:
                    return None
                elif diameter_message.name == SLR:
                    parsed_subscription_id = parse_subscription_id(diameter_message.message.subscription_id)
                    msisdn = parsed_subscription_id[0]
                    imsi = parsed_subscription_id[1]
                    # Try to check if the subscribers already exists in SessionManager
                    subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                    if not subscriber_:
                        return None
                    else:
                        diameter_message.subscriber = subscriber_
                        gx_session = session_manager.get_active_gx_session_by_msisdn(subscriber_.msisdn)
                        if not gx_session:
                            logger.error(f"GxSession active not found for msisdn: {subscriber_.msisdn}")
                            return None
                        sy_session = SySession(session_id, subscriber=subscriber_, gx_session_id=gx_session.session_id)
                        session_manager.add_sy_session(sy_session)
            else:
                # SySession found
                subscriber_ = sy_session.subscriber
                diameter_message.subscriber = subscriber_
            

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
