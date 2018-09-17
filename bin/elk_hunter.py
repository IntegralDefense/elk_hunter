#!/usr/bin/env python3

import argparse
from configparser import ConfigParser
from datetime import datetime, timedelta
import glob
import logging
import logging.config
import os
import os.path
from queue import Queue, Empty
import re
import signal
import sys
import threading
import time
import traceback
import requests
import json
requests.packages.urllib3.disable_warnings()


# custom ConfigParser to keep case sensitivity
class CaseConfigParser(ConfigParser):
    def optionxform(self, optionstr):
        return optionstr

# global variables
BASE_DIR = '/opt/elk_hunter'
RULES_DIR = [ ]
CONFIG = None

# set to True if running in daemon (scheduled) mode
DAEMON_MODE = False
# the amount of time we adjust for when running in daemon mode
GLOBAL_TIME_OFFSET = None

# utility functions

def report_error(message):
    logging.error(message)
    traceback.print_exc()

    try:
        output_dir = 'error_reporting'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f')), 'w') as fp:
            fp.write(message)
            fp.write('\n\n')
            fp.write(traceback.format_exc())

    except Exception as e:
        traceback.print_exc()

class SearchDaemon(object):
    """Executes a SearchManager in the background according to the schedules defined in the search definitions."""
    def __init__(self):
        self.shutdown = False
        self.search_manager = None
        self.thread = None
        self.thread_lock = threading.RLock()
        self.execution_slots = threading.Semaphore(CONFIG['global'].getint('max_searches'))

        # list of searches we manage
        self.managed_searches = []

    def start(self):
        self.thread = threading.Thread(target=self.run, name="SearchDaemon")
        self.thread.start()

        self.config_thread = threading.Thread(target=self.watch_config, name="SearchDaemon - config")
        self.config_thread.daemon = True
        self.config_thread.start()

    def stop(self):
        logging.info("daemon stopping...")
        self.shutdown = True

        try:
            # release anything blocking on the slots
            self.execution_slots.release()
        except:
            pass

        self.wait()

    def run(self):
        while not self.shutdown:
            try:
                self.execute()
            except Exception as e:
                report_error("uncaught exception: {0}".format(str(e)))
                time.sleep(1)

    def wait(self):
        self.thread.join()

    def execute(self):
        while not self.shutdown:
            # get a local copy of the list to use
            with self.thread_lock:
                managed_searches = self.managed_searches[:]

            for search in self.managed_searches:
                # skip searches that are disabled
                if not search.config['rule'].getboolean('enabled'):
                    continue
                # skip if it's already executing
                if search.executing:
                    continue

                # we store the time it last executed in a file
                if search.schedule_ready():
                    # wait for a slot to become ready (blocking)
                    acquire_start_time = datetime.now()
                    self.execution_slots.acquire()
                    acquire_end_time = datetime.now()
                    with open(os.path.join(BASE_DIR, 'logs', 'acquire_time_log'), 'a') as fp:
                        fp.write("{0}\t{1}\t{2}\r\n".format(search.search_name, acquire_start_time, acquire_end_time - acquire_start_time))

                    # make sure we're not shutting down
                    if self.shutdown:
                        return

                    self.execute_search(search)

            time.sleep(1.0)

    def watch_config(self):
        while True:
            try:
                self.load_searches()
            except Exception as e:
                report_error("uncaught exception when loading searches: {0}".format(str(e)))

            time.sleep(5)

    def load_searches(self):
        # add any new searches
        for rules_dir in RULES_DIR:
            for search_rule in glob.glob('{}/*.ini'.format(rules_dir)):
                search_name, _ = os.path.splitext(os.path.basename(search_rule))
                if search_name in [x.search_name for x in self.managed_searches]:
                    continue
                        
                logging.info("loading search {}".format(search_name))
                search = ELKSearch(rules_dir, search_name)
                with self.thread_lock:
                    self.managed_searches.append(search)

        # remove any searches that no longer exists
        missing_searches = []
        for search in self.managed_searches:
            if not os.path.exists(search.config_path):
                logging.warning("search {0} deleted ({1})".format(search.search_name, search.config_path))
                missing_searches.append(search)

        with self.thread_lock:
            for search in missing_searches:
                self.managed_searches.remove(search)

        # refresh all loaded searches
        for search in self.managed_searches:
            search.refresh_configuration()

    def execute_search(self, search):
        # spin off a thread to execute the search in
        t = threading.Thread(target=self._execute_search, name=search.search_name, args=(search,))
        t.daemon = True
        t.start()

    def _execute_search(self, search):
        try:
            search.execute()
        except Exception as e:
            report_error("uncaught exception when executing search {0}: {1}".format(search.search_name, str(e)))
        finally:
            self.execution_slots.release()

class ELKSearch(object):
    def __init__(self, rules_dir, search_name):
        self.rules_dir = rules_dir
        self.search_name = search_name
        self.config_path = os.path.join(self.rules_dir, '{}.ini'.format(search_name))
        self.last_executed_path = os.path.join(BASE_DIR, 'var', '{}.last_executed'.format(search_name))
        self.config = CaseConfigParser()
        self.config_timestamp = None

        # set to True in daemon mode when the search is executing
        self.executing = False

        self.refresh_configuration()

    def refresh_configuration(self):
        current_config_timestamp = os.path.getmtime(self.config_path)
        if current_config_timestamp != self.config_timestamp:
            logging.info("loading configuration for {0} from {1}".format(self.search_name, self.config_path))
            self.config_timestamp = current_config_timestamp

            if not os.path.exists(self.config_path):
                logging.warning("file {0} does not exist".format(self.config_path))
                return

            if len(self.config.read(self.config_path)) < 1:
                raise Exception("unable to read configuration file {0}".format(self.config_path))

    @property
    def last_executed_time(self):
        """Returns the last time this search was executed in daemon mode as a float value (epoch), or None if the search has not been executed."""
        try:
            with open(self.last_executed_path, 'r') as fp:
                return float(fp.read())
        except:
            return None

    @last_executed_time.setter
    def last_executed_time(self, value):
        assert isinstance(value, float)

        with open(self.last_executed_path, 'w') as fp:
            fp.write(str(value))

    def schedule_ready(self):
        """Returns True if this search need to be executed according to the schedule."""
        # does this search have a specified run time?
        now = datetime.now()

        if 'run_time' in self.config['rule']:
            # so then the next time this should run will be today at the specified timespec
            next_runtime = now
            hour, minute, second = self.config['rule']['run_time'].split(':')
            next_runtime = next_runtime.replace(hour=int(hour), minute=int(minute), second=int(second), microsecond=0)

            # have we already ran this report today?
            if self.last_executed_time is not None and datetime.fromtimestamp(self.last_executed_time) >= next_runtime:
                return False

            # is it time to run this report then?
            if now > next_runtime:
                return True

            # otherwise it is not time yet
            return False

        # if the search does not specify a runtime then we use the frequency
        # have we not ran this ever before?
        if self.last_executed_time is None:
            return True
            
        timeparts = self.config['rule']['frequency'].split(":")
        frequency = timedelta(hours=int(timeparts[0]), minutes=int(timeparts[1]), seconds=int(timeparts[2]))
        return datetime.now() > datetime.fromtimestamp(self.last_executed_time) + frequency

    def is_temporal_field(self, field):
        """Returns True if the given field is a temporal field according to the configuration."""
        try:
            return field in self.config['temporal_fields'] and self.config['temporal_fields'].getboolean(field)
        except KeyError:
            return False

    def get_field_directives(self, field):
        """Returns a list of directives for the given field (or empty list if none are defined.)"""
        try:
            return [x.strip() for x in self.config['directives'][field].split(',')]
        except KeyError:
            return []

    def execute(self, *args, **kwargs):
        start_time = None
        end_time = None

        try:
            self.executing = True
            start_time = datetime.now()
            self._execute(*args, **kwargs)
        finally:
            self.executing = False
            end_time = datetime.now()
            with open(os.path.join(BASE_DIR, 'logs', '{0}.stats'.format(self.search_name)), 'a') as fp:
                fp.write('{0}\t{1}\r\n'.format(start_time, end_time - start_time))


    #note that elasticsearch stores timestamp in utc, need to make sure the earliest & latest are in utc
    def get_time_spec_json(self,earliest,latest,use_index_time):
        # get upper limit of time range filter for query
        now = time.mktime(time.localtime())
        if latest is None:
            latest = self.config['rule']['latest']
            if DAEMON_MODE and self.config['rule'].getboolean('full_coverage') and self.last_executed_time:
                latest = datetime.utcfromtimestamp(now)
                # are we adjusting all the times backwards?
                if GLOBAL_TIME_OFFSET is not None:
                    logging.debug("adjusting timespec by {0}".format(GLOBAL_TIME_OFFSET))
                    latest = latest - GLOBAL_TIME_OFFSET
                latest = latest.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

        # get lower limit of time range filter for query
        if earliest is None:
            earliest = "{}{}".format(latest, self.config['rule']['earliest'])
            if DAEMON_MODE and self.config['rule'].getboolean('full_coverage') and self.last_executed_time:
                earliest = datetime.utcfromtimestamp(self.last_executed_time)
                # are we adjusting all the times backwards?
                if GLOBAL_TIME_OFFSET is not None:
                    logging.debug("adjusting timespec by {0}".format(GLOBAL_TIME_OFFSET))
                    earliest = earliest - GLOBAL_TIME_OFFSET
                earliest = earliest.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

        # lookup if we are supposed to use the index time or event timestamp
        if use_index_time is None:
            use_index_time = self.config['rule'].getboolean('use_index_time')

        # create time range filter for query
        if use_index_time:
            #by default @timestamp is the time the data was indexed by elasticsearch with logstash
            time_spec = { "range": { "@timestamp": { "gt": earliest, "lte": latest } } }
        else:
            #@event_timestamp is the custom field for all logs which is the  time of the event in the log that is being indexed
            time_spec = { "range": { "event_timestamp": { "gt": earliest, "lte": latest } } }

        return time_spec

   
    def search_to_json(self,search,index,filter_script,fields,earliest,latest,use_index_time,max_result_count):
        search_json = {
            'query': {
                'bool': {
                    'filter': [
                    {
                        'query_string': {
                            'query': search
                        }
                    },
                    self.get_time_spec_json(earliest,latest,use_index_time)
                    ]
                }
            }
        }
        if fields:
            search_json['_source'] = fields.split(',')
        #allow for index to not be set, many companies will create a field for the index alias instead of using elasticsearch's index pattern and just alias *
        if index:
            search_uri = "{}{}/_search".format(CONFIG['elk']['uri'],index)
        else:
            search_uri = "{}{}/_search".format(CONFIG['elk']['uri'],"*:*")
        if filter_script:
            script = { 
                'script': {
                    'script' : filter_script
                }
            }
            search_json['query']['bool']['filter'].append(script)

        # set max result count
        if max_result_count is None:
            max_result_count = self.config['rule'].getint('max_result_count')
        search_json['size'] = max_result_count

        return search_json,search_uri

    def perform_query(self,search_json,search_uri):
        # perform query
        logging.debug("executing search {} of {}".format(self.search_name, search_uri))
        logging.debug("{}".format(json.dumps(search_json)))
        headers = {'Content-type':'application/json'}
        search_result = requests.get(search_uri,data=json.dumps(search_json),headers=headers,verify=False)
        if search_result.status_code != 200:
            logging.error("search failed for {0}".format(self.search_name))
            logging.error(search_result.text)
            return False
        logging.debug("result messages: timed_out:{} - took:{} - _shards:{}".format(search_result.json()['timed_out'],search_result.json()['took'],search_result.json()['_shards']))
        return search_result

    #I have not found a way to do this from an elastic search language perspective
    #this function is used to pull configs from the search file into a dictionary for post processing of results
    def getSearchAddedFields(self,search):
        #--add-field:bat_path,command_line,\"[^\"]+\.bat\"
        #--add-field:exe_path,command_line,\"[^\"]+\.exe\"
        item = '--add-field:'
        new_fields = []
        new_field = {}
        for x in re.split('^| --',search):
            x = x.strip()
            new_field = {}
            if x.startswith(item) or x.startswith('--'+item) or x.startswith(item[2:]):
               params = x.split(":",1)[1].strip()
               new_field['new_field_name'],new_field['from_field_name'],new_field['regex'] = params.split(',',2)
               new_fields.append(new_field)
        if new_fields:
            return new_fields
        else:
            return None

    #there are times we like to add fields together to create a new field, I can't figure out how to do this in elasticsearch and still get the entire document in the output results, so doing it on the client side
    def getSearchJoinedFields(self,search):
        #--join-fields:exe_location,hostname,exe_path,@
        #--join-fields:user_account,hostname,username,--delim:,
        item = 'join-fields:'
        delimiter = ',__delim:'
        new_fields = []
        new_field = {}
        for x in re.split('^| --',search):
            x = x.strip()
            new_field = {}
            if x.startswith(item) or x.startswith('--'+item) or x.startswith(item[2:]):
               #get delimiter to join string with
               jfields,new_field['delim'] = x.split(delimiter)
               new_field['delim'] = new_field['delim'].strip().strip('\'')
               jfields = jfields.split(item)[1]
               new_field['new_field_name'],new_field['fields'] = jfields.split(",",1)
               new_fields.append(new_field)
        if new_fields:
            return new_fields
        else:
            return None

    def getSearchSplitField(self,search):        
        #--field-split:user,username,1,__delim:'\'
        item = 'field-split:'
        delimiter = ',__delim:'
        new_fields = []
        new_field = {}
        for x in re.split('^| --',search):
            x = x.strip()
            new_field = {}
            if x.startswith(item) or x.startswith('--'+item) or x.startswith(item[2:]):
               sfields,new_field['delim'] = x.split(delimiter)
               new_field['delim'] = new_field['delim'].strip().strip('\'')
               sfields = sfields.split(item)[1]
               new_field['new_field_name'],new_field['from_field_name'],new_field['array_item'] = sfields.split(',',2)
               new_fields.append(new_field)
               #logging.debug("adding field based on split: {} {} {} {}".format(new_field['new_field_name'],new_field['from_field_name'],new_field['delim'],new_field['array_item']))
        if new_fields:
            return new_fields
        else:
            return None
        
    
    def getSearchFileItem(self,search,item):
        for x in re.split('^| --',search):
            x = x.strip() 
            if x.startswith(item) or x.startswith('--'+item) or x.startswith(item[2:]):
                return x.split(":",1)[1].strip() 

        return None

    def addNewFieldsToResult(self,alert_result,added_fields):
        #print("{} {}".format(json.dumps(alert_result),json.dumps(added_fields)))
        #for any new fields defined from existing fields for output
        if added_fields:
            for field in added_fields:
                if field['from_field_name'] in alert_result['_source']:
                    regex = re.compile(field['regex'])
                    m = regex.search(alert_result['_source'][field['from_field_name']])
                    if m:
                        alert_result['_source'][field['new_field_name']] = m.group(0).strip("\"").strip()
                    else:
                        logging.debug('no match to create new field {}, with regex {}, for content {}'.format(field['new_field_name'],field['regex'],alert_result['_source'][field['from_field_name']]))
                else:
                    logging.debug('not able to add new field {}, {} does not exist'.format(field['new_field_name'],field['from_field_name']))
        return alert_result

    def addSplitFieldToResult(self,alert_result,split_fields):
        if split_fields:
            for field in split_fields:
                if field['from_field_name'] in alert_result['_source']:
                    #new field = <existing field>.split(delim)[array_item]
                    if field['delim'] in alert_result['_source'][field['from_field_name']]:
                        alert_result['_source'][field['new_field_name']] = alert_result['_source'][field['from_field_name']].split(field['delim'])[int(field['array_item'])]
                        logging.debug('created new field {}:{}'.format(field['new_field_name'],alert_result['_source'][field['new_field_name']]))
                    else:
                        logging.debug('split did not match, just copying field contents as default behavior {} {} {} {}'.format(field['from_field_name'],field['delim'],field['array_item'],alert_result['_source'][field['from_field_name']]))
                        alert_result['_source'][field['new_field_name']] = alert_result['_source'][field['from_field_name']]
        return alert_result

    def addJoinedFieldToResult(self,alert_result,joined_fields):
        if joined_fields:
            for fields in joined_fields:
                fields_exist = True
                for field in fields['fields'].split(','): #comma separated list of fields to concatentate
                    if not field in alert_result['_source']:
                        logging.warning("Join Field Error - Missing Field - {} - Not joining fields for this alert in {}".format(field,alert_result['_source'].keys()))
                        fields_exist = False
                if fields_exist:
                    build_field = ""
                    for field in fields['fields'].split(','):
                        build_field = "{}{}{}".format(build_field,alert_result['_source'][field],fields['delim'])
                    build_field = build_field[:len(build_field)-len(fields['delim'])] #take off the last delim from the loop
                    alert_result['_source'][fields['new_field_name']] = build_field
        return alert_result
        
    def _execute(self, earliest=None, latest=None, use_index_time=None, max_result_count=None):
        # read in search text
        with open(self.config['rule']['search'], 'r') as fp:
            search_text = fp.read()

        # remove comment lines starting with #
        search_text = re.sub(r'^\s*#.*$', '', search_text, count=0, flags=re.MULTILINE)

        # run the includes you might have
        while True:
            m = re.search(r'<include:([^>]+)>', search_text)
            if not m:
                break
            
            include_path = os.path.join(BASE_DIR, m.group(1))
            if not os.path.exists(include_path):
                logging.fatal("rule {0} included file {1} does not exist".format(self.search_name, include_path))
                sys.exit(1)

            with open(include_path, 'r') as fp:
                search_text = search_text.replace(m.group(0), fp.read().strip())

        search_text = search_text.replace("\n"," ")

        searches = search_text.split(" |pipe-field-output ")

        #print(searches)
        added_fields = None
        joined_fields = None
        search_index = None
        output_fields = None
        output_field_rename = None
        
        search_json = None
        now = time.mktime(time.localtime())
        #if there is only one search defined (no subsearch, no |pipe_field-output), things are easier
        #get all the supported parameters from the file and create the json needed for the search
        if len(searches) == 1:
            search_index = self.getSearchFileItem(searches[0],'--index:')
            search_query = self.getSearchFileItem(searches[0],'--search:') 
            output_fields = self.getSearchFileItem(searches[0],'--fields:')
            filter_script = self.getSearchFileItem(searches[0],'--filter-script:')
            added_fields = self.getSearchAddedFields(searches[0])
            joined_fields = self.getSearchJoinedFields(searches[0])
            split_fields = self.getSearchSplitField(searches[0])
            search_json,search_uri = self.search_to_json(search_query,search_index,filter_script,output_fields,earliest,latest,use_index_time,max_result_count)
 
        else:
            i = 0
            piped_search_output = []
            for search in searches:
                search = search.strip()
                i = i + 1
                search_index = self.getSearchFileItem(search,'--index:')
                search_query = self.getSearchFileItem(search,'--search:')
                output_fields = self.getSearchFileItem(search,'--fields:')
                filter_script = self.getSearchFileItem(search,'--filter-script:')

                added_fields = self.getSearchAddedFields(search)
                joined_fields = self.getSearchJoinedFields(search)
                split_fields = self.getSearchSplitField(search)

                output_field_rename = self.getSearchFileItem(search,'--field-rename:')
                #append previous command output to this search if not the first search
                if i > 1 and len(piped_search_output) > 0:
                    x = 0
                    for item in piped_search_output:
                        for key,value in item.items():
                            if x == 0: 
                                if search_query.strip() != "":
                                    search_query = '{} AND ({}:"{}"'.format(search_query,key,value)
                                else: #if no additional search text
                                    search_query = '({}:"{}"'.format(key,value)
                                x = x + 1
                            else:
                                search_query = '{} OR {}:"{}"'.format(search_query,key,value)
                    search_query = '{})'.format(search_query)
                    #reinitialize so output isn't used again accidentally
                    piped_search_output = []

                search_json,search_uri = self.search_to_json(search_query,search_index,filter_script,output_fields,earliest,latest,use_index_time,max_result_count)

                #if not the last search, perform the query, rename fields if needed
                if i != len(searches):
                    search_json['size'] = 10000
                    logging.debug("lucene search: {}".format(search_query))
                    search_result = self.perform_query(search_json,search_uri)
                    if not search_result:
                        if DAEMON_MODE:
                            self.last_executed_time = now
                        return False
                    results = search_result.json()["hits"]["hits"]
                    # if no results, then don't search again, just quit, but make sure we log that we ran it
                    if not results:
                        if DAEMON_MODE:
                            self.last_executed_time = now
                        return False
                    deduped_output = set()
                    if len(search_result.json()["hits"]["hits"]) > 9999:
                        logging.error("piped search results too big. >= 10000 results (elasticsearch limit). Exiting.")
                        if DAEMON_MODE:
                            self.last_executed_time = now
                        return False
                    for hit in results:
                        #if we are changing the field name, change it in the results
                        if output_field_rename:
                            current_field,new_field = output_field_rename.split(',')
                            current_hit = hit['_source'][current_field]
                            hit['_source'][new_field] = current_hit
                            del hit['_source'][current_field] 
                        #only add items that do not exist (dedup/unique)
                        deduped_output.add(json.dumps(hit['_source']))
                    for n in deduped_output:
                        piped_search_output.append(json.loads(n))

        logging.debug("lucene search: {}".format(search_query))
        search_result =  self.perform_query(search_json,search_uri)
        if not search_result:
            return False

        # record the fact that we ran it
        if DAEMON_MODE:
            self.last_executed_time = now

        # get group by value
        if 'group_by' in self.config['rule']:
            group_by_value = self.config['rule']['group_by']
        else:
            group_by_value = None

        # group results
        alerts = {}
        tmp_key = 0
        results = search_result.json()["hits"]["hits"]
        for alert_result in results:
            combined_results = {}
            #####for any new fields defined from existing fields for output
            if added_fields:
                alert_result = self.addNewFieldsToResult(alert_result,added_fields) 
            if split_fields:
                alert_result = self.addSplitFieldToResult(alert_result,split_fields)
            if joined_fields:
                alert_result = self.addJoinedFieldToResult(alert_result,joined_fields)
            ####
            
            if "_source" in alert_result:
                combined_results.update(alert_result["_source"])
            if "fields" in alert_result:
                combined_results.update(alert_result["fields"])
            if group_by_value is None:
                alerts[tmp_key] = [combined_results]
                tmp_key += 1
            elif group_by_value in combined_results:
                if isinstance(combined_results[group_by_value], list):
                    tmp_key = ", ".join(combined_results[group_by_value])
                else:
                    tmp_key = combined_results[group_by_value]
                if tmp_key not in alerts:
                    alerts[tmp_key] = []
                alerts[tmp_key].append(combined_results)
            else:
                alerts["null"] = combined_results
        if alerts:
            logging.debug("{}".format(json.dumps(alerts)))
        else:
            logging.debug("no results")

        for alert_key in alerts.keys():
            alert_title = '{} - {}'.format(self.config['rule']['name'], alert_key)

            # alert type defaults to elk but you can override
            alert_type = 'elk'
            if 'type' in self.config['rule']:
                alert_type = self.config['rule']['type']

            alert = Alert(
                tool='elk',
                tool_instance='elk_hunter',
                alert_type=alert_type,
                desc=alert_title,
                event_time=time.strftime("%Y-%m-%d %H:%M:%S"),
                #details=alert_key,
                details=alerts[alert_key],
                name=self.config['rule']['name'],
                company_name=CONFIG['ace']['company_name'],
                company_id=CONFIG['ace'].getint('company_id'))

            # extract tags
            if 'tags' in self.config['rule']:
                for tag in self.config['rule']['tags'].split(','):
                    alert.add_tag(tag)

            # extract observables
            for observables in alerts[alert_key]:
                # is this observable type a temporal type?
                o_time = observables['_time'] if '_time' in observables else None
                if o_time is not None:
                    m = re.match(r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]{3}[-+][0-9]{2}:[0-9]{2}$', o_time)
                    if not m:
                        logging.error("_time field does not match expected format: {0}".format(o_time))
                    else:
                        # reformat this time for ACE
                        o_time = '{0}-{1}-{2} {3}:{4}:{5}'.format(
                            m.group(1),
                            m.group(2),
                            m.group(3),
                            m.group(4),
                            m.group(5),
                            m.group(6))

                for o_field in self.config['observable_mapping'].keys():
                    if o_field not in observables:
                        logging.debug("field {} does not exist in event with observables {}".format(o_field,observables))
                        continue

                    o_type = self.config['observable_mapping'][o_field]
                    if isinstance(observables[o_field], list):
                        o_values = observables[o_field]
                    else:
                        o_values = [ observables[o_field] ]

                    for o_value in o_values:
                        # ignore values that are None, empty string or a single -
                        if o_value is None:
                            continue

                        # make sure this is a string
                        if not isinstance(o_value, str):
                            o_value = str(o_value)

                        if o_value.strip() == '' or o_value.strip() == '-':
                            continue

                        alert.add_observable(o_type, 
                                             o_value, 
                                             o_time if self.is_temporal_field(o_field) else None, 
                                             directives=self.get_field_directives(o_field))

            if CONFIG['ace'].getboolean('enabled'):
                try:
                    logging.info("submitting alert {}".format(alert.description))
                    alert.submit(CONFIG['ace']['uri'], CONFIG['ace']['key'])
                except Exception as e:
                    logging.error("unable to submit alert {}: {}".format(alert, str(e)))

            logging.debug(str(alert))

        return True

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Elk Hunter")
    parser.add_argument('-b', '--base-directory', required=False, default=None, dest='base_dir',
        help="Path to the base directory of the Elk Hunter tool. "
        "Defaults to /opt/elk_hunter. "
        "Override with ELK_HUNTER environment variable.")
    parser.add_argument('-c', '--config', required=False, default='etc/elk_hunter.ini', dest='config_path',
        help="Path to configuration file.  Defaults to etc/elk_hunter.ini")
    parser.add_argument('--logging-config', required=False, default='etc/logging.ini', dest='logging_config',
        help="Path to logging configuration file.  Defaults to etc/logging.ini")
    parser.add_argument('-r', '--rules-dir', required=False, dest='rules_dir', action='append', default=[],
        help="Path to rules directory. More than one can be specified. Defaults to rules/")

    parser.add_argument('-d', '--daemon', required=False, default=False, action='store_true', dest='daemon',
        help="Start as daemon running automated searches.  Defaults to running individual searches as specified.")
    parser.add_argument('--background', required=False, default=False, action='store_true', dest='background',
        help="Run the background as a service.  Only applies to --daemon.")
    parser.add_argument('-k', '--kill', required=False, default=False, action='store_true', dest='kill',
        help="Kill a running daemon.")

    parser.add_argument('--earliest', required=False, default=None, dest='earliest',
        help="Replace configuration specific earliest time.  Time spec absolute format is MM/DD/YYYY:HH:MM:SS")
    parser.add_argument('--latest', required=False, default=None, dest='latest',
        help="Replace configuration specific latest time.")
    parser.add_argument('-i', '--use-index-time', required=False, default=None, action='store_true', dest='use_index_time',
        help="Use __index time specs instead.")

    parser.add_argument("searches", nargs=argparse.REMAINDER, help="One or more searches to execute.")

    #subparsers = parser.add_subparsers(dest='command') #title='subcommands', help='additional help')
    #manual_search_commands = [ 'cli_search']
    #manual_search_parser = subparsers.add_parser('cli_search',help='search with command line')
    #manual_search_parser.add_argument('--search',action='store',required=True,help='the lucene search')
    #manual_search_parser.add_argument('--index',action='store',required=True,help='the elasticsearch index to search')
    #manual_search_parser.add_argument('--fields',action='store',help='print the following fields instead of the entire output <comma delimited list of fieldsi>')
    #manual_search_parser.add_argument('--add-field',action='store',help='3 arguments comma separated. <new_field_name>,<field_name_to_match>,<regex to match>')
    #manual_search_parser.add_argument('--join-fields-with',action='store',help='comma separated list of fields to join with the last item in the list being a character or string to join fields with <jar_location,hostname,jar_file,@')

    args = parser.parse_args()

    # initialize environment

    if 'ELK_HUNTER' in os.environ:
        BASE_DIR = os.environ['ELK_HUNTER']
    if args.base_dir:
        BASE_DIR = args.base_dir

    try:
        os.chdir(BASE_DIR)
    except Exception as e:
        sys.stderr.write("ERROR: unable to cd into {0}: {1}\n".format(
            BASE_DIR, str(e)))
        sys.exit(1)

    # make sure all the directories exists that need to exist
    for path in [os.path.join(BASE_DIR, x) for x in ['error_reporting', 'logs', 'var']]:
        if not os.path.isdir(path):
            try:
                os.mkdir(path)
            except Exception as e:
                sys.stderr.write("ERROR: cannot create directory {0}: {1}\n".format(
                    path, str(e)))
                sys.exit(1)

    # remove proxy if it's set
    if 'http_proxy' in os.environ:
        del os.environ['http_proxy']
    if 'https_proxy' in os.environ:
        del os.environ['https_proxy']

    # load lib/ onto the python path
    sys.path.append('lib')

    from saq.client import Alert

    if args.kill:
        daemon_path = os.path.join(BASE_DIR, 'var', 'daemon.pid')
        if os.path.exists(daemon_path):
            with open(daemon_path, 'r') as fp:
                daemon_pid = int(fp.read())

            os.kill(daemon_pid, signal.SIGKILL)
            print("killed pid {0}".format(daemon_pid))

            try:
                os.remove(daemon_path)
            except Exception as e:
                sys.stderr.write("ERROR: unable to delete {0}: {1}\n".format(daemon_path, str(e)))

            sys.exit(0)
        else:
            print("WARNING: no running instance available to kill")
            sys.exit(0)
    
    # are we running as a deamon/
    if args.daemon and args.background:

        pid = None

        # http://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
        try:
            pid = os.fork()
        except OSError as e:
            logging.fatal("{0} ({1})".format(e.strerror, e.errno))
            sys.exit(1)

        if pid == 0:
            os.setsid()

            try:
                pid = os.fork()
            except OSError as e:
                logging.fatal("{0} ({1})".format(e.strerror, e.errno))
                sys.exit(1)

            if pid > 0:
                # write the pid to a file
                with open(os.path.join(BASE_DIR, 'var', 'daemon.pid'), 'w') as fp:
                    fp.write(str(pid))

                os._exit(0)
        else:
            os._exit(0)

        import resource
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = MAXFD

            for fd in range(0, maxfd):
                try:
                    os.close(fd)
                except OSError:   # ERROR, fd wasn't open to begin with (ignored)
                    pass

        if (hasattr(os, "devnull")):
            REDIRECT_TO = os.devnull
        else:
            REDIRECT_TO = "/dev/null"

        os.open(REDIRECT_TO, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)

    # initialize logging
    try:
        logging.config.fileConfig(args.logging_config)
    except Exception as e:
        sys.stderr.write("ERROR: unable to load logging config from {0}: {1}".format(
            args.logging_config, str(e)))
        sys.exit(1)

    # load configuration
    CONFIG = CaseConfigParser()
    try:
        CONFIG.read(args.config_path)
    except Exception as e:
        logging.fatal("unable to load configuration from {0}: {1}".format(
            args.config_path, str(e)))
        sys.exit(1)

    if args.rules_dir:
        RULES_DIR = args.rules_dir
        
    RULES_DIR = [os.path.join(BASE_DIR, _dir) for _dir in RULES_DIR]

    if CONFIG['global']['global_time_offset'] != '':
        hours, minutes, seconds = [int(x) for x in CONFIG['global']['global_time_offset'].split(':')]
        GLOBAL_TIME_OFFSET = timedelta(hours=hours, minutes=minutes, seconds=seconds)
        logging.debug("using global time delta {0}".format(GLOBAL_TIME_OFFSET))

    if args.daemon:
        DAEMON_MODE = True
        daemon = SearchDaemon()
        daemon.start()

        try:
            daemon.wait()
        except KeyboardInterrupt:
            daemon.stop()
            daemon.wait()

        sys.exit(0)

    # otherwise we run each search by itself
    if len(args.searches) < 1:
        logging.fatal("Specify which searches you want to run.")
        sys.exit(1)

    search_object = None

    try:
        for search_name in args.searches:
            for rules_dir in RULES_DIR:
                for search_result in glob.glob('{0}/*{1}*.ini'.format(rules_dir, search_name)):
                    search_name, _ = os.path.splitext(os.path.basename(search_result))
                    search_object = ELKSearch(rules_dir, search_name)
                    search_object.execute(earliest=args.earliest, latest=args.latest, use_index_time=args.use_index_time)
    except KeyboardInterrupt:
        pass
