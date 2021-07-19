#!/usr/bin/python
# Copyright: (c) 2019, Whitney Champion <whitney.ellis.champion@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_streams
short_description: Communicate with the Graylog API to manage streams
description:
    - The Graylog streams module manages Graylog streams.
version_added: "2.9"
author: "Whitney Champion (@shortstack)"
options:
  graylog_fqdn:
    description:
      - Graylog endoint. (i.e. graylog.mydomain.com).
    required: false
    type: str
  graylog_port:
    description:
      - Graylog API TCP port. (i.e. 9000).
    required: false
    type: str
  graylog_user:
    description:
      - Graylog privileged user username.
    required: false
    type: str
  graylog_password:
    description:
      - Graylog privileged user password.
    required: false
    type: str
  allow_http:
    description:
      - Allow non HTTPS connexion
    required: false
    default: false
    type: bool    
  validate_certs:
    description:
      - Allow untrusted certificate
    required: false
    default: false
    type: bool      
  action:
    description:
      - Action to take against stream API.
    required: false
    default: list
    choices: [ create_stream, create_rule, start_stream, pause_stream, update_stream, update_rule, delete_stream, delete_rule, list_streams, query_streams ]
    type: str
  title:
    description:
      - Stream title.
    required: false
    type: str
  description:
    description:
      - Stream description.
    required: false
    type: str
  stream_id:
    description:
      - Stream ID.
    required: false
    type: str
  rule_id:
    description:
      - Rule ID.
    required: false
    type: str
  index_set_id:
    description:
      - Index set ID.
    required: false
    type: str
  matching_type:
    description:
      - Matching type for the stream rules.
    required: false
    type: str
  remove_matches_from_default_stream:
    description:
      - Remove matches from default stream, true or false.
    required: false
    default: False
    type: bool
  stream_name:
    description:
      - Stream name to use with the query_streams action.
    required: false
    type: str
  field:
    description:
      - Field name for the stream rule to check.
    required: false
    type: str
  type:
    description:
      - Rule type for the stream rule, 1-7.
    required: false
    default: 1
    type: int
  value:
    description:
      - Value to check rule against.
    required: false
    type: str
  inverted:
    description:
      - Invert rule (must not match value).
    required: false
    default: False
    type: bool
  rules:
    description:
      - List of rules associated with a stream.
    required: false
    type: list
'''

EXAMPLES = '''
# List streams
- graylog_streams:
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"

# Get stream from stream name query_streams
- graylog_streams:
    action: query_streams
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_name: "test_stream"
  register: stream

# List single stream by ID
- graylog_streams:
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"

# Create stream
- graylog_streams:
    action: create
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    title: "Client XYZ"
    description: "Windows and IIS logs"
    matching_type: "AND"
    remove_matches_from_default_stream: False
    rules:
      - '{"field":"message", "type":"6", "value":"test", "inverted":true, "description":"testrule"}'

# Update stream
- graylog_streams:
    action: update
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"
    remove_matches_from_default_stream: True

# Create stream rule
- graylog_streams:
    action: create_rule
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"
    description: "Windows Security Logs"
    field: "winlogbeat_log_name"
    type: 1
    value: "Security"
    inverted: False

# Start stream
- graylog_streams:
    action: start_stream
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"

# Pause stream
- graylog_streams:
    action: pause_stream
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"

# Update stream rule
- graylog_streams:
    action: update_rule
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"
    rule_id: "{{ rule.json.id }}"
    description: "Windows Security and Application Logs"

# Delete stream rule
- graylog_streams:
    action: delete_rule
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"
    rule_id: "{{ rule.json.id }}"

# Delete stream
- graylog_streams:
    action: delete
    graylog_fqdn: "graylog.mydomain.com"
    graylog_port: "9000"
    graylog_user: "username"
    graylog_password: "password"
    stream_id: "{{ stream.json.id }}"
'''

RETURN = '''
json:
  description: The JSON response from the Graylog API
  returned: always
  type: complex
  contains:
    title:
      description: Stream title.
      returned: success
      type: str
      sample: 'Windows Logs'
    alert_conditions:
      description: Alert conditions.
      returned: success
      type: dict
      sample: |
        [
            {
                "created_at": "2018-10-18T18:40:21.582+0000",
                "creator_user_id": "admin",
                "id": "cc43d4e7-e7b2-4abc-7c44-4b29cadaf364",
                "parameters": {
                    "backlog": 1,
                    "grace": 0,
                    "repeat_notifications": true,
                    "threshold": 0,
                    "threshold_type": "MORE",
                    "time": 1
                },
                "title": "Failed Logon",
                "type": "message_count"
            }
        ]
    alert_receivers:
        description: Alert receivers.
        returned: success
        type: dict
        sample: '{ "emails": [], "users": [] }'
    content_pack:
        description: Content pack.
        returned: success
        type: str
        sample: null
    created_at:
        description: Stream creation time.
        returned: success
        type: str
        sample: "2018-10-17T15:29:20.735Z"
    creator_user_id:
        description: Stream creator.
        returned: success
        type: str
        sample: "admin"
    description:
        description: Stream description.
        returned: success
        type: str
        sample: "Stream for Windows logs"
    disabled:
        description: Whether or not the stream is enabled.
        returned: success
        type: bool
        sample: false
    id:
        description: Stream ID.
        returned: success
        type: str
        sample: "5bc7666089675c7f7d7f08d7"
    index_set_id:
        description: Index set ID associated with the stream.
        returned: success
        type: str
        sample: "4bc7444089575c7f7d7f08d7"
    is_default:
        description: Whether or not it is the default stream.
        returned: success
        type: bool
        sample: false
    matching_type:
        description: Stream rule matching type.
        returned: success
        type: str
        sample: "AND"
    outputs:
        description: Stream outputs.
        returned: success
        type: dict
        sample: []
    remove_matches_from_default_stream:
        description: Whether or messages are removed from the default stream.
        returned: success
        type: bool
        sample: false
    rules:
        description: Rules associated with the stream.
        returned: success
        type: dict
        sample: []
status:
  description: The HTTP status code from the request
  returned: always
  type: int
  sample: 200
url:
  description: The actual URL used for the request
  returned: always
  type: str
  sample: https://www.ansible.com/
'''


# import module snippets
import json
import base64
from urllib.parse import urlparse, urlunparse, urljoin
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text


def create(module, streams_url, headers, index_set_id):
    #TODO: call query_stream from here to check for existing streams similar to create_rule func
    # this will remove the need for Ansible playbook idempotency contortions
    url = streams_url

    payload = {}

    for key in ['title', 'description', 'remove_matches_from_default_stream', 'matching_type', 'rules']:
        if module.params[key] is not None and module.params[key] != "":
            payload[key] = module.params[key]

    payload['index_set_id'] = index_set_id

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST', data=module.jsonify(payload))

    if info['status'] != 201:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url

def query_rules(module, streams_url, headers):
    """
    Check for rules in a given stream with matching field and value settings.
    If they exist, return the rule ID, if not return rule_id="0"
    :param module: Ansible module configuration settings
    :type module: dict
    :param streams_url: Graylog API URL
    :type streams_url: string
    :param headers: HTTP headers to be sent with API req
    :type headers: dict
    :return: HTTP status code and msg, response body, and API endpoint called
    :rtype: tuple
    """
    rules_path = "/".join([module.params['stream_id'], "rules"])
    url = urljoin(streams_url, rules_path)
    payload = {}

    field = module.params['field']
    value = module.params['value']
    #raise Exception(module.params['field'])

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')
    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        rules = json.loads(content)
        #raise Exception(rules)
    except IOError:
        raise IOError("Server response not readable")

    if rules['stream_rules']:
        for rule in rules['stream_rules']:
            if field == rule['field'] and value == rule['value']:
                rule_id = dict(rule_id=rule['id'])
                #raise Exception(rule_id)
                break
            else:
                rule_id = dict(rule_id=False)
    else:
        rule_id = dict(rule_id=False)

    content = json.dumps(rule_id)
    return info['status'], info['msg'], content, url

def create_rule(module, streams_url, headers):
    """
    Create a stream rule after checking for existing rules with same field and value settings
    :param module: Ansible module configuration settings
    :type module: dict
    :param streams_url: Graylog API URL
    :type streams_url: string
    :param headers: HTTP headers to be sent with API req
    :type headers: dict
    :return: HTTP status code and msg, response body, and API endpoint called
    :rtype: tuple
    """

    status, message, content, url = query_rules(module, streams_url, headers)
    query_result = json.loads(content)
    #raise Exception(query_result)
    if 'rule_id' in query_result:
        rules_path = "/".join([module.params['stream_id'], "rules"])
        url = urljoin(streams_url, rules_path)

        if not query_result['rule_id']:
            payload = {}
            for key in ['field', 'type', 'value', 'inverted', 'description']:
                if module.params[key] is not None:
                    payload[key] = module.params[key]
           #TODO: the following 9 lines are duplicated 4x, turn into a helper function?
            response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST', data=module.jsonify(payload))

            if info['status'] != 201:
                module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

            try:
                content = to_text(response.read(), errors='surrogate_or_strict')
            except AttributeError:
                content = info.pop('body', '')
        else:
            info = dict(url=url, status=200, msg="stream rule exists")

    else:
        raise Exception("Key 'rule_id' not present in 'query_result' dict.")

    return info['status'], info['msg'], content, url


def update(module, streams_url, headers, stream_id, title, description, remove_matches_from_default_stream, matching_type, rules, index_set_id):

    url = "/".join([streams_url, stream_id])

    payload = {}

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        payload_current = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    if title is not None:
        payload['title'] = title
    else:
        payload['title'] = payload_current['title']
    if description is not None:
        payload['description'] = description
    else:
        payload['description'] = payload_current['description']
    if remove_matches_from_default_stream is not None:
        payload['remove_matches_from_default_stream'] = remove_matches_from_default_stream
    else:
        payload['remove_matches_from_default_stream'] = payload_current['remove_matches_from_default_stream']
    if matching_type is not None:
        payload['matching_type'] = matching_type
    else:
        payload['matching_type'] = payload_current['matching_type']
    if rules is not None:
        payload['rules'] = rules
    else:
        payload['rules'] = payload_current['rules']
    if index_set_id is not None:
        payload['index_set_id'] = index_set_id
    else:
        payload['index_set_id'] = payload_current['index_set_id']

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='PUT', data=module.jsonify(payload))

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def update_rule(module, streams_url, headers, stream_id, rule_id, field, type, value, inverted, description):

    payload = {}

    url = "/".join([streams_url, stream_id, "rules", rule_id])

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        payload_current = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    if field is not None:
        payload['field'] = field
    else:
        payload['field'] = payload_current['field']
    if type is not None:
        payload['type'] = type
    else:
        payload['type'] = payload_current['type']
    if value is not None:
        payload['value'] = value
    else:
        payload['value'] = payload_current['value']
    if inverted is not None:
        payload['inverted'] = inverted
    else:
        payload['inverted'] = payload_current['inverted']
    if description is not None:
        payload['description'] = description
    else:
        payload['description'] = payload_current['description']

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='PUT', data=module.jsonify(payload))

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def delete_stream(module, streams_url, headers):
    """
    Delete graylog stream by stream_id
    :param module: Ansible module configuration settings
    :type module: dict
    :param streams_url: Graylog streams API URL
    :type streams_url: string
    :param headers: HTTP headers to be sent with API req
    :type headers: dict
    :return: HTTP status code and msg, response body, and API endpoint called
    :rtype: tuple
    """

    url = urljoin(streams_url, module.params['stream_id'])
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def delete_rule(module, streams_url, headers):
    """
     Delete graylog stream rule with matching field and value settings by rule_id
     :param module: Ansible module configuration settings
     :type module: dict
     :param streams_url: Graylog streams API URL
     :type streams_url: string
     :param headers: HTTP headers to be sent with API req
     :type headers: dict
     :return: HTTP status code and msg, response body, and API endpoint called
     :rtype: tuple
    """
    status, message, content, url = query_rules(module, streams_url, headers)
    query_result = json.loads(content)
    rules_path = "/".join([module.params['stream_id'], "rules", query_result['rule_id']])
    url = urljoin(streams_url, rules_path)
    #raise Exception(url)
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def start_stream(module, streams_url, headers):

    path = "/".join([module.params['stream_id'], 'resume'])
    url = urljoin(streams_url, path)
    #raise Exception(url)

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def pause_stream(module, streams_url, headers):

    path = "/".join([module.params['stream_id'], 'pause'])
    url = urljoin(streams_url, path)
    #raise Exception(url)

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST')

    if info['status'] != 204:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def list(module, streams_url, headers, stream_id):
    if stream_id is not None:
        url = urljoin(streams_url, stream_id)
    else:
        url = streams_url

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def query_streams(module, streams_url, headers, stream_name):

    url = streams_url

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        streams = json.loads(content)
    except IOError:
        raise IOError("Server response not readable")

    if streams is not None:
        for stream in streams['streams']:
            if stream_name == stream['title']:
                stream_json = {'stream_id': stream['id']}
                break
            else:
                stream_json = {'stream_id': '0'}

    content = json.dumps(stream_json)
    return info['status'], info['msg'], content, url


def default_index_set(module, base_url, headers):

    url = "%s/api/system/indices/index_sets?skip=0&limit=0&stats=false" % (base_url)

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))
    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        indices = json.loads(content)
        default_index_set_id = ""
        if indices is not None:
            default_index_set_id = indices['index_sets'][0]['id']
    except AttributeError:
        content = info.pop('body', '')

    return default_index_set_id


def get_token(module, base_url, username, password):

    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json" }'

    url = urljoin(base_url, "/api/system/sessions")

    payload = {
        'username': username,
        'password': password,
        'host': base_url
    }
    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='POST', data=module.jsonify(payload))

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        session = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    session_string = session['session_id'] + ":session"
    session_bytes = session_string.encode('utf-8')
    session_token = base64.b64encode(session_bytes)

    return session_token


def main():
    module = AnsibleModule(
        argument_spec=dict(
            protocol=dict(type='str', required=False, default='http', choices=['http', 'https']),
            graylog_fqdn=dict(type='str'),
            graylog_port=dict(type='str'),
            base_uri=dict(type='str', required=False, default='/api/streams/'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            allow_http=dict(type='bool', required=False, default=False),
            validate_certs=dict(type='bool', required=False, default=True),
            action=dict(type='str', required=False, default='list', choices=['create', 'create_rule', 'start_stream', 'pause_stream',
                        'update_stream', 'update_rule', 'delete_stream', 'delete_rule', 'list', 'query_streams', 'query_rules']),
            stream_id=dict(type='str'),
            stream_name=dict(type='str'),
            rule_id=dict(type='str'),
            title=dict(type='str'),
            field=dict(type='str'),
            type=dict(type='int', default=1),
            value=dict(type='str'),
            index_set_id=dict(type='str'),
            inverted=dict(type='bool', default=False),
            description=dict(type='str'),
            remove_matches_from_default_stream=dict(type='bool', default=False),
            matching_type=dict(type='str'),
            rules=dict(type='list')
        )
    )

    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    action = module.params['action']
    stream_id = module.params['stream_id']
    stream_name = module.params['stream_name']
    rule_id = module.params['rule_id']
    title = module.params['title']
    field = module.params['field']
    type = module.params['type']
    value = module.params['value']
    index_set_id = module.params['index_set_id']
    inverted = module.params['inverted']
    description = module.params['description']
    remove_matches_from_default_stream = module.params['remove_matches_from_default_stream']
    matching_type = module.params['matching_type']
    rules = module.params['rules']
    url = module.params['graylog_fqdn'] + ':' + module.params['graylog_port']

    url_bits = (module.params['protocol'], url, '', '', '', '')
    base_url = urlunparse(url_bits)
    #raise Exception(base_url)
    streams_url = urljoin(base_url, module.params['base_uri'])
    #raise Exception(streams_url)

    api_token = get_token(module, base_url, graylog_user, graylog_password)
    headers = '{ "Content-Type": "application/json", \
                 "X-Requested-By": "Graylog API", \
                 "Accept": "application/json", \
                 "Authorization": "Basic ' + api_token.decode() + '" }'
    #TODO: is there a way to get rid of this cond block?
    # seems like could call the func named in the playbook if all func params were identical?
    if action == "create":
        if index_set_id is None:
            index_set_id = default_index_set(module, base_url, headers)
        status, message, content, url = create(module, streams_url, headers, index_set_id)
    elif action == "create_rule":
        status, message, content, url = create_rule(module, streams_url, headers)
    elif action == "update":
        status, message, content, url = update(module, streams_url, headers, stream_id, title, description, remove_matches_from_default_stream, matching_type, rules, index_set_id)
    elif action == "update_rule":
        status, message, content, url = update_rule(module, streams_url, headers, stream_id, rule_id, field, type, value, inverted, description)
    elif action == "delete_stream":
        status, message, content, url = delete_stream(module, streams_url, headers)
    elif action == "delete_rule":
        status, message, content, url = delete_rule(module, streams_url, headers)
    elif action == "start_stream":
        status, message, content, url = start_stream(module, streams_url, headers)
    elif action == "pause_stream":
        status, message, content, url = pause_stream(module, streams_url, headers)
    elif action == "list":
        status, message, content, url = list(module, streams_url, headers, stream_id)
    elif action == "query_streams":
        status, message, content, url = query_streams(module, streams_url, headers, stream_name)
    elif action == "query_rules":
        status, message, content, url = query_rules(module, streams_url, headers)
    else:
        raise IOError('Action is not in playbook list of allowed choices.')

    uresp = {}
    content = to_text(content, encoding='UTF-8')

   # check that HTTP response body is valid JSON as req'd by Ansible
    try:
        js = json.loads(content)
    except ValueError:
        js = ""

    uresp['json'] = js
    uresp['status'] = status
    uresp['msg'] = message
    uresp['url'] = url

    module.exit_json(**uresp)


if __name__ == '__main__':
    main()
