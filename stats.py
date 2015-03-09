#!/usr/bin/env python2

import re
import subprocess
from pprint import pprint
import sys
from contextlib import contextmanager
import time
import itertools

_log_parts = re.compile(r'^(?P<date>\S+) (?P<hostname>\w+) (?P<daemon>\S+)\[(?P<pid>\d+)\]: (?P<message>.*)$')
_message_id = re.compile(r'^[0-9A-F]{10}')

@contextmanager
def timer(message):
    sys.stderr.write(message)
    sys.stderr.write(' ')
    sys.stderr.flush()
    t1 = time.time()
    yield
    t2 = time.time()
    sys.stderr.write('{0} ms\n'.format(int((t2 - t1) * 1000)))
    sys.stderr.flush()

def get_records():
    with timer('running journalctl...'):
        logs = subprocess.check_output(['/usr/bin/journalctl', '--unit=postfix.service', '--output=short-iso', '--since=2015-02-01'])
    with timer('splitting lines...'):
        logs = logs.split('\n')[1:-1]
    with timer('parsing records...'):
        return [ _log_parts.match(line).groupdict() for line in logs ]

def find_connects_and_pickups(records):
    session_id = 1
    for rec in records:
        if rec['daemon'] == 'postfix/smtpd' and rec['message'].startswith('connect from '):
            rec['session_id'] = session_id
            session_id += 1
        elif rec['daemon'] == 'postfix/pickup':
            rec['session_id'] = session_id
            session_id += 1
        else:
            rec['session_id'] = 0

def find_disconnects(records):
    last_session_id = 0
    for (i, rec) in enumerate(records):
        if rec['session_id'] <= last_session_id:
            continue
        if rec['daemon'] != 'postfix/smtpd':
            continue
        j = i + 1
        while True:
            if records[j]['daemon'] == 'postfix/smtpd' and records[j]['pid'] == rec['pid']:
                records[j]['session_id'] = rec['session_id']
                if records[j]['message'].startswith('disconnect from '):
                    break
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

def session_dict(records):
    return { session_id: [ records[i] for i in record_indices ]
             for (session_id, record_indices) in session_index(records).items() }

def follow_queue(records):
    index = session_index(records)
    for (session_id, rec_numbers) in index.items():
        for i in rec_numbers:
            if records[i]['daemon'] == 'postfix/pickup':
                message_id = records[i]['message'][:10]
                break
            elif records[i]['daemon'] == 'postfix/smtpd' and _message_id.match(records[i]['message']):
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
    print '{i:4} {date} {hostname} {daemon}[{pid}]: {message}'.format(i=rec['session_id'] or '', **rec)

class Matcher(object):
    def __init__(self, name, *transitions):
        self.name = name
        self.trans = { k: [ (next_state, daemon, re.compile(regex or r'^.*$')) for (_, next_state, daemon, regex) in v ]
                       for (k, v) in itertools.groupby(transitions, lambda t: t[0]) }

    def __call__(self, records, state=0):
        result = { 'type': self.name }
        for rec in records:
            for (next_state, daemon, regex) in self.trans[state]:
                if rec['daemon'] != daemon: continue # wrong daemon
                match = regex.match(rec['message'])
                if not match: continue # wrong log message
                result.update(match.groupdict())
                state = next_state
                break # found it, so stop searching
            else:
                break # didn't find it, so give up
        else:
            if state == 42: return result # reached end of state machine, so return result
        return None

_session_rules = [
    Matcher('LOCAL_TO_LOCAL_DELIVERED',
            (0, 1,  'postfix/pickup',   r''),
            (1, 2,  'postfix/cleanup',  r''),
            (2, 3,  'postfix/qmgr',     r'^[0-9A-F]{10}: from=<(?P<from>\S+)>, size=\d+, nrcpt=\d+ \(queue active\)$'),
            (3, 4,  'postfix/local',    r''),
            (4, 42, 'postfix/qmgr',     r'^[0-9A-F]{10}: removed$')),

    Matcher('LOCAL_TO_REMOTE_DELIVERED',
            (0, 1,  'postfix/pickup',   r''),
            (1, 2,  'postfix/cleanup',  r''),
            (2, 3,  'postfix/qmgr',     r'^[0-9A-F]{10}: from=<(?P<from>\S+)>, size=\d+, nrcpt=\d+ \(queue active\)$'),
            (3, 4,  'postfix/smtp',     r''),
            (4, 42, 'postfix/qmgr',     r'^[0-9A-F]{10}: removed$')),

    Matcher('REMOTE_TO_LOCAL_GREYLISTED',
            (0, 1,  'postfix/smtpd',    r'^connect from .+$'),
            (1, 2,  'postfix/smtpd',    r'^NOQUEUE: reject.*Greylisted;.*$'),
            (2, 2,  'postfix/smtpd',    r'^NOQUEUE: reject.*Greylisted;.*$'),
            (2, 42, 'postfix/smtpd',    r'^disconnect from .+$')),

    Matcher('REMOTE_TO_LOCAL_HELO_REJECTED',
            (0, 1,  'postfix/smtpd',    r'^connect from .+$'),
            (1, 2,  'postfix/smtpd',    r'^NOQUEUE: reject.*Helo command rejected:.*$'),
            (2, 2,  'postfix/smtpd',    r'^lost connection after .*$'),
            (2, 42, 'postfix/smtpd',    r'^disconnect from .+$'))
]

def classify_sessions(records):
    def classify(session):
        for matcher in _session_rules:
            result = matcher(session)
            if result: return result
    return { session_id: classify(session)
             for (session_id, session) in session_dict(records).items() }

if __name__ == '__main__':
    records = get_records()

    with timer('finding connects and pickups...'):
        find_connects_and_pickups(records)

    with timer('finding disconnects...'):
        find_disconnects(records)

    with timer('following queues...'):
        follow_queue(records)

    with timer('matching patterns...'):
        patterns = classify_sessions(records)

    sys.stderr.write('done\n\n')

    # TODO : policyd-spf
    # TODO : anvil statistics
    # TODO : warning hostname does not resolve to address

    #map(print_record, records)

    index = session_index(records)
    for session_id in sorted(index.keys()):
        for i in index[session_id]:
            print_record(records[i])
        if patterns[session_id]:
            print ' -->', patterns[session_id]
        print
