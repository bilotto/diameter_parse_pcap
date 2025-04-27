import sys
import os
from typing import *
from diameter.message import dump
from DiamTelecom.diameter import *
# from DiamTelecom.telecom import *
from DiamTelecom import SessionManager
from DiamTelecom.diameter.constants import *
#
from ._parse_functions import *
from .csv_file import CsvFile


import threading
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
                             create_subscribers: bool,
                             csv_file: CsvFile,
                             lock: threading.Lock,
                             ):
    try:
        subscriber_ = None
        session_id = diameter_message.message.session_id
        gx_session = None
        framed_ip_address = None
        framed_ipv6_prefix = None
        framed_ip = None

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
                    session_manager.add_subscriber(Subscriber(msisdn, msisdn, imsi))
                    subscriber_ = session_manager.get_subscriber_by_msisdn(msisdn)
                if diameter_message.message.framed_ip_address:
                    framed_ip_address = bytes_to_ip(diameter_message.message.framed_ip_address)
                elif diameter_message.message.framed_ipv6_prefix:
                    framed_ipv6_prefix = decode_framed_ipv6(diameter_message.message.framed_ipv6_prefix)
                else:
                    raise Exception(f"Framed-IP-Address not found in {diameter_message.name}: {subscriber_}")
                if framed_ip_address:
                    gx_session = GxSession(subscriber_, session_id, framed_ip_address, apn)
                    if hasattr(diameter_message.message, 'sgsn_mcc_mnc'):
                        gx_session.set_mcc_mnc(diameter_message.message.sgsn_mcc_mnc)
                    if framed_ipv6_prefix:
                        gx_session.framed_ipv6_prefix = framed_ipv6_prefix
                elif framed_ipv6_prefix:
                    gx_session = GxSession(subscriber_, session_id, None, apn)
                    if hasattr(diameter_message.message, 'sgsn_mcc_mnc'):
                        gx_session.set_mcc_mnc(diameter_message.message.sgsn_mcc_mnc)
                    gx_session.framed_ipv6_prefix = framed_ipv6_prefix
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
        with lock:
            try:
                write_to_csv(csv_file, diameter_message)
            except Exception as e:
                logger.error(f"Error writing to csv file - Error : {e}")
                logger.error(dump(diameter_message))
                raise e

        return True
    except Exception as e:
        logger.error(f"Error processing diameter message: {e}")
        logger.error(dump(diameter_message))
        raise e
