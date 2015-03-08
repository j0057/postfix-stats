#!/usr/bin/env python2

import re
import subprocess
from pprint import pprint
import sys

_log_parts = re.compile(r'^(?P<date>\S+) (?P<hostname>\w+) (?P<sid>\S+)\[(?P<pid>\d+)\]: (?P<message>.*)$')
_message_id = re.compile(r'^[0-9A-F]{10}')

def get_logs():
    sys.stderr.write('  running journalctl\n')
    logs = subprocess.check_output(['/usr/bin/journalctl', '--unit=postfix.service', '--output=short-iso', '--since=2015-02-01'])
    sys.stderr.write('  splitting lines\n')
    logs = logs.split('\n')[1:-1]
    sys.stderr.write('  parsing records\n')
    return [ _log_parts.match(line).groupdict() for line in logs ]

def find_connects_and_pickups(logs):
    session_id = 1
    for rec in logs:
        if rec['message'].startswith('connect from'):
            rec['session_id'] = session_id
            session_id += 1
        elif rec['sid'] == 'postfix/pickup':
            rec['session_id'] = session_id
            session_id += 1
        else:
            rec['session_id'] = 0

def find_disconnects(records):
    last_session_id = 0
    for (i, rec) in enumerate(records):
        if rec['session_id'] <= last_session_id: continue
        if rec['sid'] != 'postfix/smtpd': continue
        j = i + 1
        while True:
            if records[j]['sid'] == 'postfix/smtpd' and records[j]['pid'] == rec['pid']:
                records[j]['session_id'] = rec['session_id']
                if records[j]['message'].startswith('disconnect from'): break
            j += 1
        last_session_id = rec['session_id']

def session_index(records):
    result = {}
    for (i, rec) in enumerate(records):
        session_id = rec['session_id']
        if not session_id:
            continue
        if session_id in result:
            result[session_id].append(i)
        else:
            result[session_id] = [i]
    return result

def follow_queue(records):
    index = session_index(records)
    for (session_id, rec_numbers) in index.items():
        for i in rec_numbers:
            if records[i]['sid'] == 'postfix/pickup':
                message_id = records[i]['message'][:10]
                break
            elif records[i]['sid'] == 'postfix/smtpd' and _message_id.match(records[i]['message']):
                message_id = records[i]['message'][:10]
                break
        else:
            continue
        while True:
            if records[i]['message'].startswith(message_id):
                records[i]['session_id'] = session_id
                if records[i]['message'].endswith(': removed'):
                    break
            i += 1

def print_record(rec):
    print '{i:4} {date} {hostname} {sid}[{pid}]: {message}'.format(i=rec['session_id'] or '', **rec)

if __name__ == '__main__':
    sys.stderr.write('getting records\n')
    logs = get_logs()

    sys.stderr.write('finding connects and pickups\n')
    find_connects_and_pickups(logs)

    sys.stderr.write('finding disconnects\n')
    find_disconnects(logs)

    sys.stderr.write('following queues\n')
    follow_queue(logs)

    sys.stderr.write('done\n\n')

    # TODO : policyd-spf
    # TODO : anvil statistics
    # TODO : warning hostname does not resolve to address

    #map(print_record, logs)

    index = session_index(logs)
    for session_id in sorted(index.keys()):
        for i in index[session_id]:
            print_record(logs[i])
        print
