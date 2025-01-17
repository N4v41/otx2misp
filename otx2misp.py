#!/usr/bin/env python
import configparser
import argparse
import sys
import os
import pickle
from OTXv2 import OTXv2
from pymisp import PyMISP, MISPEvent, PyMISPError
from datetime import date, datetime, timedelta
from dateutil.parser import *
from helper import *

# disable verify SSL warnings
try:
    import urllib3
    urllib3.disable_warnings()
except:
    pass


def config_parser(section, key):
    config = configparser.ConfigParser()
    try:
        config.read(os.getcwd()+"/config/config.ini")
        result = config.get(section, key)
        return result
    except config.NoOptionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")
    except config.NoSectionError:
        raise Exception("There was a problem with configuration file. The key does not exist.")


def load_file(filename):
    with open(os.getcwd() + "/config/" + filename, "r") as ins:
        array = []
        for line in ins:
            array.append(line.strip())
        ins.close()
    return array


def misp_connection(url, misp_key, proxy_usage):
    try:
        if proxy_usage:
            proxies = {}
            proxies ["http"] = config_parser("misp","http")
            proxies ["https"] = config_parser("misp","https")
            misp = PyMISP(url, misp_key, False, 'json', proxies=proxies)
        else:
            misp = PyMISP(url, misp_key, False, 'json',None)
    except PyMISPError:
        print("\t [!] Error connecting to MISP instance. Check if your MISP instance it's up!")
        return None

    return misp

def new_misp_event(event_name):
    event = MISPEvent()
    event.distribution = 0
    event.threat_level_id = 1
    event.analysis = 0
    event.info = event_name
    event.add_tag("OTX")
    return event

def create_event(misp, event_name, dedup_events):
    if dedup_events:
        result = misp.search(eventinfo=event_name)
        if len(result) == 0:
            print("\t [!] Dedup parameter is active but event not exist on target misp, creating new event")
            event = new_misp_event(event_name)
            event_new = True
            return event, event_new
        else:
            for evt in result:
                # If it exists, set 'event' to the existing event
                if evt['Event']['info'] == event_name:
                    if 'SharingGroup' in evt:
                        del evt['Event']['SharingGroup']
                    event_new = False
                    event = MISPEvent()
                    event.load(evt)
                    return event, event_new
    else:
        event = new_misp_event(event_name)
        event_new = True
        return event, event_new


def check_if_empty_att(att):
    empty = False
    if type(att) == list and len(att) == 0:
        empty = True
    elif (att == None) or (att == " ") or (att == ''):
        empty = True
    else:
        empty = False
    return empty

#function to map pulse iocs to misp format
def map_iocs(event, pulse):
    attribute_map = {
    'IPv4': 'ip-src',
    'IPv6': 'ip-src',
    'domain': 'domain',
    'YARA': 'yara',
    'hostname': 'hostname',
    'email': 'email',
    'URL': 'url',
    'MUTEX': 'mutex',
    'CVE': 'other',
    'FileHash-MD5': 'md5',
    'FileHash-SHA1': 'sha1',
    'FileHash-SHA256': 'sha256',
    'FileHash-PEHASH': 'pehash',
    'FileHash-IMPHASH': 'imphash'
    }

    for ioc in pulse['indicators']:
        attribute_name = attribute_map.get(ioc['type'], 'other')
        if attribute_name == 'other':
            event.add_attribute(attribute_name, "CVE: " + ioc['indicator'])
        elif attribute_name == 'ip-src':
            if ioc['title'] != '404 NOT FOUND' and ioc['title'] != '':
                event.add_attribute(attribute_name, ioc['title'])
            else:
                event.add_attribute(attribute_name, ioc['indicator'])
        elif attribute_name == 'yara':
            event.add_attribute(attribute_name, ioc['content'])
        else:
            event.add_attribute(attribute_name, ioc['indicator'])
    return event


def send2misp(pulse, proxy_usage, dedup_events):
    url = config_parser("misp", "url")
    api_key = config_parser("misp", "api_key")
    misp = misp_connection(url, api_key, proxy_usage)
    event_name = pulse['name']
    event, event_new = create_event(misp, event_name, dedup_events)
    event.add_attribute('other', "This Pulse was created on:" + pulse['created'])
    if pulse['modified']:
        event.add_attribute('other', "This Pulse was edited on:" + pulse['modified'])

    #add Tag to events
    tlp = "tlp:"+pulse['tlp']
    
    event.add_tag(tlp)
    if len(pulse['tags']) > 0:
        for t in pulse['tags']:
            event.add_tag(t)


    #check if attributes exist if not add
    if not check_if_empty_att(pulse['description']):
        event.add_attribute("other", "Description: "+ pulse['description'])
    if not check_if_empty_att(pulse['malware_families']):
        event.add_attribute("other", "Malware families: " + str(pulse['malware_families']))
    if not check_if_empty_att(pulse['targeted_countries']):
        event.add_attribute("other", "targeted countries: " + str(pulse['targeted_countries']))
    if not check_if_empty_att(pulse['adversary']):
        event.add_attribute("other", "Adversary: " + pulse['adversary'])
    if not check_if_empty_att(pulse['attack_ids']):
        event.add_attribute("other", "MITRE ATT&CK techniques used: " + str(pulse['attack_ids']))
    if not check_if_empty_att(pulse['references']):
        for r in pulse['references']:
            event.add_attribute("link", r)

    #user the map ioc function to normalize event iocs
    event = map_iocs(event, pulse)

    #check if event has id and update, else add event
    if 'id' in event:
        misp_event = misp.update_event(event, pythonify=True)
        print("\t [*] Event with ID " + str(misp_event.id) + " has been successfully updated in MISP.")
    else:
        misp_event = misp.add_event(event, pythonify=True)
        print("\t [*] Event with ID " + str(misp_event.id) + " has been successfully stored in MISP.")


def filter_pulse_by_attck_technique(pulse, techniques_list):
    contains_technique = False
    for k in techniques_list:
        if k in pulse['attack_ids']:
            return True

    return contains_technique


def filter_pulse_by_keyword(pulse, keywords_list):
    contains_alerts = False
    for k in keywords_list:
        if (k in pulse['name']) or k in (pulse['description']) or (k.replace(" ", "") in pulse['tags']):
            return True

    return contains_alerts

def pulse_cache(api, max_days, cache_pulse, use_cached_pulse):
    # if max_days :
    #     start_date = datetime.now() - timedelta(days=max_days)
    #     start_date_tp = start_date.time()
    #     pulses = api.getall(modified_since=start_date_tp)
    #     return pulses
    #else:
    if cache_pulse:
        pulses = api.getall()
        #export pulses list to file
        with open(os.getcwd() + "/otx_pulses.cache", 'wb') as f:
            pickle.dump(pulses, f)
        return pulses
    elif use_cached_pulse:
        #import pulses list from file
        with open(os.getcwd() + "/otx_pulses.cache", 'rb') as f:
            pulses = pickle.load(f)
        return pulses
    else:
        pulses = api.getall()
        return pulses

def search_on_otx(api, alerts, techniques, max_days, cache_pulse, use_cached_pulse, c_or_m_pulses):
    pulse_list = []
    keywords_list = load_file("keywords.txt")
    techniques_list = load_file("attack_ids.txt")
    today = date.today()
    date_today = today.strftime("%Y-%m-%d")
    now = parse(date_today)
    print("[*] Searching for Pulses on OTX:")
    pulses = pulse_cache(api, max_days, cache_pulse, use_cached_pulse)
    ###needs a better logic
    #if the parameter max days was passed get only events with modification in the time window


    for pulse in pulses:
        if c_or_m_pulses:
            threat_c = parse(pulse['created'])
            c_days = now - threat_c
            threat_m = parse(pulse['modified'])
            m_days = now - threat_m
            d_filter = m_days.days <= int(max_days) or c_days.days <= int(max_days)
        else:
            threat_c = parse(pulse['created'])
            c_days = now - threat_c
            d_filter = c_days.days <= int(max_days)

        if d_filter:
            if alerts:
                if techniques:
                    contains_alert = filter_pulse_by_keyword(pulse, keywords_list)
                    contains_technique = filter_pulse_by_attck_technique(pulse, techniques_list)
                    if contains_technique or contains_alert:
                        show_pulse(pulse, verbosity)
                        pulse_list.append(pulse)
                else:
                    contains_alert = filter_pulse_by_keyword(pulse, keywords_list)
                    if contains_alert:
                        show_pulse(pulse, verbosity)
                        pulse_list.append(pulse)
            elif techniques:
                contains_technique = filter_pulse_by_attck_technique(pulse, techniques_list)
                if contains_technique:
                    show_pulse(pulse, verbosity)
                    pulse_list.append(pulse)

            else:
                show_pulse(pulse, verbosity)
                pulse_list.append(pulse)

    print("[*] Number of OTX Pulses gathered: " + str(len(pulse_list)))
    return pulse_list


def start_listen_otx():
    api_key = config_parser("otx", "api_key")
    otx_server = config_parser("otx", "otx_server")
    api = OTXv2(api_key, server=otx_server)
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--alerts", help=" Filter OTX pulses gathered in case of a match with any "
                                               "keywords of your list.",
                                               action="store_true")
    parser.add_argument("-d", "--days", help=" Filter OTX pulses by days (e.g. Last 7 days: -d 7 )")
    parser.add_argument("-all", "--all_pulses", help="Get all subscribed Pulses", action="store_true")
    parser.add_argument("-m", "--misp", help="Send IoCs from OTX to MISP", action="store_true")
    parser.add_argument("-mdd", "--misp_dedup", help="Send IoCs from OTX to MISP deduplicating events", action="store_true")
    parser.add_argument("-p", "--proxy", help="Set a proxy for sending the alert to your MISP instance..",
                        action="store_true")
    parser.add_argument("-ccp", "--cache_pulse", help="Cache pulse list to improve testing performance", action="store_true")
    parser.add_argument("-ucp", "--use_cached_pulse", help="Use cached pulse list", action="store_true")
    parser.add_argument("-p_cm", "--get_pulses_new_or_mod", help="Get pulses created or modified in the range", action="store_true")
    parser.add_argument("-t", "--techniques", help=" Filter OTX pulses gathered in case of a match with any "
                                               "ATT&CK techniques of your list.",
                                               action="store_true")
    parser.add_argument("-v", "--verbose", dest="verbose",
                    action="count", default=0,
                    help="Verbosity, repeat to increase the verbosity level.")                                           
    args = parser.parse_args()
    
    #define verbosity as global variable
    global verbosity
    if args.verbose <= 1:
        verbosity = 1
    elif args.verbose == 2:
        verbosity = 2
    else :
        verbosity = 3

    proxy_usage = False
    if args.days:
        max_days = args.days
    else:
        max_days = 7

    c_or_m_pulses = args.get_pulses_new_or_mod
    dedup_events = args.misp_dedup
    cache_pulse = args.cache_pulse
    use_cached_pulse = args.use_cached_pulse


    #python function to determine proxy usage and send pulses to misp
    def send_to_misp(pulses, proxy_usage, dedup_events):
        if args.misp:
            if args.proxy:
                proxy_usage = True
            print("[*] Sending alerts to MISP")
            for t in pulses:
                send2misp(t, proxy_usage, dedup_events)


    if args.alerts:
        print("[*] Checking if the pulses gathered contain any keyword from your list.")
        if args.techniques:
            pulses = search_on_otx(api, True, True, max_days, cache_pulse, use_cached_pulse, c_or_m_pulses)
        else:
            pulses = search_on_otx(api, True, False, max_days, cache_pulse, use_cached_pulse, c_or_m_pulses)
        send_to_misp(pulses, proxy_usage, dedup_events)
        sys.exit(0)

    elif args.techniques:
        print("[*] Checking if the pulses gathered contain any ATT&CK Technique from your list.")
        pulses = search_on_otx(api, False, True, max_days, cache_pulse, use_cached_pulse, c_or_m_pulses)
        send_to_misp(pulses, proxy_usage, dedup_events)
        sys.exit(0)

    else:
        print("[*] Checking and sending subscribed pulses gathered.")
        pulses = search_on_otx(api, False, False, max_days, cache_pulse, use_cached_pulse, c_or_m_pulses)
        send_to_misp(pulses, proxy_usage, dedup_events)
        sys.exit(0)


if __name__ == '__main__':
    start_listen_otx()
