#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, LO3 Energy, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
module: graylog_inputs
short_description: Manage Graylog inputs
description:
    - The Graylog inputs module allows configuration of inputs nodes.
version_added: "2.9"
author: "Matthieu SIMON"
options:
  graylog_fqdn:
    description:
      - Graylog endoint. (i.e. graylog.mydomain.com).
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
  protocol:
    description:
      - http or https
    required: false
    default: http
    type: str
  validate_certs:
    description:
      - Allow untrusted certificate
    required: false
    default: true
    type: bool
  action:
    description:
      - Action to take against system/input API.
      - Warning : when update, all settings with default value set in this Ansible module (like bind_address, port ...) will replace existing values
        You must explicitly set these values if they differ from those by default
    required: true
    default: create
    choices: [ create, update ]
    type: str
  log_format:
    description:
      - Log event format or source (not all are implemented at this time)
    required: true
    choices: [ 'GELF', 'Syslog', 'Cloudtrail', 'Cloudwatch' ]
    type: str
  input_protocol:
    description:
      - Input type (not all are implemented at this time)
    required: true
    default: UDP
    choices: [ 'UDP', 'TCP', 'HTTP', 'Cloudtrail', 'Cloudwatch' ]
    type: str
  title:
    description:
      - Entitled of the input
      - Required with actions create, update and delete
    required: true
    type: str
  input_id:
    description:
      - ID of input to update
    required: false
    type: str
  global_input:
    description:
      - Input is present on all Graylog nodes
    required: false
    default: true
    type: bool
  node:
    description:
      - Node name if input is not global
    required: false
    type: str
  bind_address:
    description:
      - Address to listen on
    required: false
    default: "0.0.0.0"
    type: str
  port:
    description:
      - Port to listen on
    required: true
    default: 12201
    type: int
   number_worker_threads:
    description:
      - Number of worker threads processing network connections for this input.
    required: false
    default: 2
    type: int
  override_source:
    description:
      - The source is a hostname derived from the received packet by default. Set this if you want to override it with a custom string.
    required: false
    type: str
  recv_buffer_size:
    description:
      - The size in bytes of the recvBufferSize for network connections to this input.
    required: false
    default: 1048576
    type: int
  store_full_message:
    description:
      - Store the full original syslog message as full_message
    required: false
    default: false
    type: bool
  tcp_keepalive:
    description:
      - Enable TCP keepalive packets (TCP & HTTP only)
    required: false
    default: false
    type: bool
  tls_enable:
    description:
      - Accept TLS connections (TCP & HTTP only)
    required: false
    default: false
    type: bool
  tls_cert_file:
    description:
      - Path to the TLS certificate file (TCP & HTTP only)
    required: false
    type: str
  tls_key_file:
    description:
      - Path to the TLS private key file (TCP & HTTP only)
    required: false
    type: str
  tls_key_password:
    description:
      - The password for the encrypted key file. (TCP & HTTP only)
    required: false
    type: str
  tls_client_auth:
    description:
      - Whether clients need to authenticate themselves in a TLS connection (TCP & HTTP only)
    required: false
    default: disabled
    choices: [ 'disabled', 'optional', 'required' ]
  tls_client_auth_cert_file:
    description:
      - TLS Client Auth Trusted Certs (File or Directory) (TCP & HTTP only)
    required: false
    type: str
  use_null_delimiter:
    description:
      - Use null byte as frame delimiter ? Otherwise newline delimiter is used. (TCP Only)
    required: false
    default: false
    type: bool
  decompress_size_limit:
    description:
      - The maximum number of bytes after decompression.
    required: false
    default: 8388608
    type: int
  enable_cors:
    description:
      - Input sends CORS headers to satisfy browser security policies (HTTP Only)
    required: false
    default: true
    type: bool
  idle_writer_timeout:
    description:
      - The server closes the connection after the given time in seconds after the last client write request. (use 0 to disable) (HTTP Only)
    required: false
    default: 60
    type: int
  max_chunk_size:
    description:
      - The maximum HTTP chunk size in bytes (e. g. length of HTTP request body) (HTTP Only)
    required: false
    default: 65536
    type: int
  max_message_size:
    description:
      - The maximum length of a message. (TCP Only)
    required: false
    default: 2097152
    type: int
  extractors:
    description:
      - object describing extractors for input.
    required: false
    type: dict
'''

EXAMPLES = '''

  - name: Display all inputs
    graylog_input:
      graylog_fqdn: "{{ graylog_endpoint }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      protocol: "https"
      validate_certs: "false"
      action: "list"

  - name: Remove input with ID 1df0f1234abcd0000d0adf20
    graylog_inputs:
      graylog_fqdn: "{{ graylog_endpoint }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      protocol: "http"
      action: "delete"
      input_id: "1df0f1234abcd0000d0adf20"
  - name: Create GELF HTTP input
    graylog_inputs:
      action: "create"
      allow_http: "true"
      graylog_fqdn: "{{ graylog_fqdn }}"
      graylog_port: "{{ graylog_port }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      title: "Test input GELF HTTP"
      log_format: "GELF"
      input_protocol: "HTTP"
      bind_address: "0.0.0.0"
      validate_certs: "false"
      global_input: "true"

  # Create input with json extractor. Currently only json,
  # regex and split_and_index supported. Example extractors variable
  # in vars.yml below
  vars.yml:
  extractors: {"some_extractor":{"key_prefix":"","key_separator":"_","key_whitespace_replacement":"_","kv_separator":"=","list_separator":",","replace_key_whitespace":false,"source_field":"message","type":"json"}}

  - name: Create input and extractors
    graylog_inputs:
      graylog_fqdn: "{{ graylog_server }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      graylog_port: '9000'
      action: "{{ action | default('create') }}"
      title: "Gelf input"
      port: "12000"
      log_format: "GELF"
      input_protocol: "{{ input_protocol | default('UDP') }}"
      extractors: "{{ extractors }}"
'''

# import module snippets
import json
import base64
import sys
# from urllib.parse import urlunparse, urljoin
if sys.version_info < (3, 0):
    from urlparse import urlunparse, urljoin
else:
    from urllib.parse import urlunparse, urljoin
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text
import re

def list(module, inputs_url, headers):

    url = inputs_url
    input_id = module.params['input_id']
    if input_id is not None:
        url = urljoin(url, input_id)
    else:
        url = url

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        #raise Exception(content)
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url



def query_inputs(module, inputs_url, headers):

    url = inputs_url
    input_id = dict(input_id=False)
    title = module.params['title']

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        data = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    regex = r"^" + re.escape(title) + r"$"

    #TODO: match on more than just title, add port, log_format, input_protocol
    for input in data['inputs']:
      if re.match(regex, input['title']) is not None:
         input_id = dict(input_id=input['id'])

    content = json.dumps(input_id)

    return info['status'], info['msg'], content, inputs_url

def get_input_id(module, inputs_url, headers):

    url = inputs_url
    input_id = dict(input_id=False)
    title = module.params['title']

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))
        return

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        data = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    regex = r"^" + re.escape(title) + r"$"

    #TODO: match on more than just title, add port, log_format, input_protocol
    if len(data['inputs']) > 0:
        for input in data['inputs']:
          if re.match(regex, input['title']) is not None:
             input_id['input_id'] = input['id']
          # else:
          #     input_id = {}

    # input_id = json.dumps(input_id)

    return info['status'], info['msg'], input_id

def create_extractors(module, url, headers, method, name, conf):
    try:
        input_status, input_msg, input_id = get_input_id(module, url, headers)
    except Exception as e:
        module.fail_json(msg="Unknown error: %s" % ("Status: , Message: " + str(e) + " greska2: "))

    extractor_url = url + input_id['input_id'] + "/extractors"

    if conf.get('cursor_strategy') != None:
        cursor_strategy = conf['cursor_strategy']
    else:
        cursor_strategy = 'copy'



    configuration = {}

    if conf['type'] == 'regex':
        for key in ['regex_value']:
            if conf[key] is not None:
                configuration[key] = conf[key]
    elif conf['type'] == 'json':
        for key in ['list_separator', 'kv_separator', 'key_prefix', 'key_separator', 'replace_key_whitespace',
                     'key_whitespace_replacement']:
            if conf[key] is not None:
                configuration[key] = conf[key]
    elif conf['type'] == 'split_and_index':
        for key in ['split_by', 'index']:
            if conf[key] is not None:
                configuration[key] = conf[key]
    else:
        module.fail_json(msg="Error: %s" % (conf['type'] + " is not supported extractor type"))



    payload = {}
    payload['title'] = name
    payload['cut_or_copy'] = cursor_strategy
    payload['source_field'] = conf['source_field']
    if conf.get('target_field') != None:
        payload['target_field'] = conf['target_field']
    else:
        payload['target_field'] = 'none'
    payload['extractor_type'] = conf['type']
    payload['extractor_config'] = configuration
    payload['converters'] = {}
    payload['cut_or_copy'] = cursor_strategy
    if conf.get('order') != None:
        payload['order'] = conf['order']
    payload['condition_type'] = "none"
    payload['condition_value'] = ""

    try:
        response, info = fetch_url(module=module, url=extractor_url, headers=json.loads(headers), method=method, data=module.jsonify(payload))
    except Exception as e:
        module.fail_json(msg="Unknown error: %s" % ("Status: , Message: " + str(e)))

    if info['status'] != 201:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body']) + ", URL: " + extractor_url))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url


def create_input(module, inputs_url, headers):
    """
     Check if an input with same title exists, if so update/PUT it, if not create/POST it.
    :param module: Ansible playbook parameters
    :type module: str
    :param inputs_url: Graylog API URL
    :type inputs_url: str
    :param headers: HTTP Headers to be sent to Graylog API
    :type headers: dict
    :return: HTTP Response Code, message, response body, and API URL
    :rtype: tuple
    """

    url = inputs_url
    log_format = module.params['log_format']

    status, message, content, url = query_inputs(module, url, headers)
    query_result = json.loads(content)

    if 'input_id' in query_result:
        if query_result['input_id']:
            module.exit_json(changed=False)
        else:
           httpMethod = "POST"

    configuration = {}

    #TODO: add flags TCP, UDP, HTTP, Cloudwatch, Cloudtrail,
    if log_format == "gelf":
        if module.params['input_protocol'] == "TCP":
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
        elif module.params['input_protocol'] == "UDP":
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
        else:
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.http.GELFHttpInput"
        for key in ['bind_address', 'port', 'number_worker_threads', 'override_source', 'recv_buffer_size',
                     'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password',
                     'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter', 'decompress_size_limit',
                     'enable_cors', 'idle_writer_timeout', 'max_chunk_size', 'max_message_size']:
            if module.params[key] is not None:
                configuration[key] = module.params[key]
    elif log_format == "syslog":
        for key in ['bind_address', 'port', 'allow_override_date', 'expand_structured_data', 'force_rdns',
                     'number_worker_threads', 'override_source', 'recv_buffer_size', 'store_full_message',
                     'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password',
                     'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter']:
            if module.params['input_protocol'] == "UDP":
                module.params['input_protocol'] = "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
            else:
                module.params['input_protocol'] = "org.graylog2.inputs.syslog.tcp.SyslogTCPInput"
            if module.params[key] is not None:
                configuration[key] = module.params[key]
    elif log_format == "cloudtrail":
        raise IOError("Cloudtrail input not implemented yet :(")
    elif log_format == "cloudwatch":
        raise IOError("Cloudwatch input not implemented yet :(")

    payload = {}

    payload['type'] = module.params['input_protocol']
    payload['title'] = module.params['title']
    payload['global'] = module.params['global_input']
    payload['node'] = module.params['node']
    payload['configuration'] = configuration

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method=httpMethod, data=module.jsonify(payload))

    if info['status'] != 201:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    for extractor_name, extractor_dict in module.params['extractors'].items():
        try:
            status, msg, content_extr, url = create_extractors(module=module, url=url, headers=headers, method=httpMethod, name=extractor_name, conf=extractor_dict)
        except AttributeError:
            content_extr = info_extr.pop('body', '')

    return info['status'], info['msg'], content, inputs_url
    # return status, msg, content_extr, url

def list_extractors(module, inputs_url, headers):
    # Example endpoint: http://127.0.0.1:9000/api/system/inputs/60f096d3062742757d8958c0/extractors

    #url = inputs_url + "/" + module.params['input_id'] + "/extractors"

    path = "/".join([module.params['input_id'], 'extractors'])
    url = urljoin(inputs_url, path)

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))
    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
    except AttributeError:
        content = info.pop('body', '')

    return info['status'], info['msg'], content, url

#TODO: define create_extractors func, not sure how to handle json files, templates or build with dicts, or ?

#TODO: define create_static_fields func

def delete_input(module, inputs_url, headers):

    status, message, input_id = get_input_id(module, inputs_url, headers)
    info = {}
    info = { "status": "", "msg" : "" }
    content = ""
    url = ""

    if input_id['input_id'] != False:

        url = inputs_url + input_id['input_id']

        response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='DELETE')

        if info['status'] != 204:
            module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body']) + ", URL: " + url))

        try:
            content = to_text(response.read(), errors='surrogate_or_strict')
        except AttributeError:
            content = info.pop('body', '')

    return info['status'], info['msg'], content, url



def get_token(module, endpoint, username, password):

    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json" }'

    url = endpoint + "/system/sessions"

    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['host'] = endpoint

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
            action=dict(type='str', default='list',
                        choices=['create', 'update', 'list', 'list_extractors', 'delete', 'query_inputs']),
            protocol=dict(type='str', required=False, default='http', choices=['http', 'https']),
            graylog_fqdn=dict(type='str'),
            graylog_port=dict(type='str'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            force=dict(type='bool', required=False, default=False),
            log_format=dict(type='str', required=False, default='gelf',
                                choices=['gelf', 'syslog', 'cloudtrail', 'cloudwatch']),
            input_protocol=dict(type='str', required=False, default='UDP',
                        choices=[ 'UDP', 'TCP', 'HTTP' ]),
            title=dict(type='str', required=False ),
            input_id=dict(type='str', required=False),
            global_input=dict(type='bool', required=False, default=True),
            node=dict(type='str', required=False),
            bind_address=dict(type='str', required=False, default='0.0.0.0'),
            port=dict(type='int', required=False, default=12201),
            base_uri=dict(type='str', required=False, default='/api/system/inputs/'),
            allow_override_date=dict(type='bool', required=False, default=False),
            expand_structured_data=dict(type='bool', required=False, default=False),
            force_rdns=dict(type='bool', required=False, default=False),
            number_worker_threads=dict(type='int', required=False, default=2),
            override_source=dict(type='str', required=False),
            recv_buffer_size=dict(type='int', required=False, default=1048576),
            store_full_message=dict(type='bool', required=False, default=False),
            tcp_keepalive=dict(type='bool', required=False, default=False),
            tls_enable=dict(type='bool', required=False, default=False),
            tls_cert_file=dict(type='str', required=False),
            tls_key_file=dict(type='str', required=False),
            tls_key_password=dict(type='str', required=False, no_log=True),
            tls_client_auth=dict(type='str', required=False, default='disabled',
                        choices=[ 'disabled', 'optional', 'required' ]),
            tls_client_auth_cert_file=dict(type='str', required=False),
            use_null_delimiter=dict(type='bool', required=False, default=False),
            decompress_size_limit=dict(type='int', required=False, default=8388608),
            enable_cors=dict(type='bool', required=False, default=True),
            idle_writer_timeout=dict(type='int', required=False, default=60),
            max_chunk_size=dict(type='int', required=False, default=65536),
            max_message_size=dict(type='int', required=False, default=2097152),
            extractors=dict(type='dict', required=False)
        )
    )

    # build common urls
    url = module.params['graylog_fqdn'] + ':' + module.params['graylog_port']
    url_bits = (module.params['protocol'], url, '/api', '', '', '')
    base_url = urlunparse(url_bits)
    #raise Exception(base_url)
    inputs_url = urljoin(base_url, module.params['base_uri'])
    #raise Exception(inputs_url)

    api_token = get_token(module, base_url, module.params['graylog_user'], module.params['graylog_password'])
    headers = '{ "Content-Type": "application/json", \
                 "X-Requested-By": "Graylog API", \
                 "Accept": "application/json", \
                 "Authorization": "Basic ' + api_token.decode() + '" }'

    action = module.params['action']

    if action == "list":
       # if index_set_id is None:
       #     index_set_id = default_index_set(module, endpoint, headers)
        status, message, content, url = list(module, inputs_url, headers)
    elif action == "create":
        # create the input if one with same title does not exist
        status, message, content, url = create_input(module, inputs_url, headers)
    elif action == "list_extractors":
        status, message, content, url = list_extractors(module, inputs_url, headers)
    elif action == "delete":
        status, message, content, url = delete_input(module, inputs_url, headers)
    elif action == "query_inputs":
        status, message, content, url = query_inputs(module, inputs_url, headers)
    else:
        raise IOError('Action is not in playbook list of allowed choices.')

    uresp = {}
    content = to_text(content, encoding='UTF-8')

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
