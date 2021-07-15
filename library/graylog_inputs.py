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
  endpoint:
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
    default: GELF
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
'''

EXAMPLES = '''
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

  # this is from the rsyslog file, POST/PUT are combined in this version
  - name: Update existing input
    graylog_input_rsyslog:
      action: "update"
      allow_http: "true"
      graylog_fqdn: "{{ graylog_fqdn }}"
      graylog_port: "{{ graylog_port }}"
      graylog_user: "{{ graylog_user }}"
      graylog_password: "{{ graylog_password }}"
      title: "Rsyslog TCP"
      validate_certs: "false"
      input_protocol: "TCP"
      global_input: "true"
      allow_override_date: "true"
      expand_structured_data: "false"
      force_rdns: "true"
      port: "1514"
      store_full_message: "true"
      input_id: "1df0f1234abcd0000d0adf20"
'''

# import module snippets
import json
import base64
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, to_text
import re

def query_inputs(module, base_url, headers, title):

    url = base_url
    inputExist = False

    response, info = fetch_url(module=module, url=url, headers=json.loads(headers), method='GET')

    if info['status'] != 200:
        module.fail_json(msg="Fail: %s" % ("Status: " + str(info['msg']) + ", Message: " + str(info['body'])))

    try:
        content = to_text(response.read(), errors='surrogate_or_strict')
        data = json.loads(content)
    except AttributeError:
        content = info.pop('body', '')

    regex = r"^" + re.escape(title) + r"$"

    for graylogInputs in data['inputs']:
      if re.match(regex, graylogInputs['title']) is not None:
        inputExist = True

    return inputExist


def create_input(module, base_url, headers):
    """
     Check if an input with same title exists, if so update/PUT it, if not create/POST it.
    :param module: Ansible playbook parameters
    :type module: str
    :param base_url: Graylog API URL
    :type base_url: str
    :param headers: HTTP Headers to be sent to Graylog API
    :type headers: dict
    :return: HTTP Response Code, message, response body, and API URL
    :rtype: tuple
    """

    url = base_url

    if module.params['action'] == "create":
      inputExist = query_inputs(module, base_url, headers, module.params['title'])
      if inputExist == True:
        #TODO: use this exit_json in streams module also!
        module.exit_json(changed=False)
      httpMethod = "POST"
    else:
      httpMethod = "PUT"
      url = base_url + "/" + module.params['input_id']

    configuration = {}
   #TODO: add conditionals here based on new module param log_format to accomodate all input types, no need to created separate functions for each afaik
    # flags: TCP, UDP, HTTP, Cloudwatch, Cloudtrail,
    if input_type == "gelf":
        for key in [ 'bind_address', 'port', 'number_worker_threads', 'override_source', 'recv_buffer_size', \
                 'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password', \
                 'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter', 'decompress_size_limit', \
                 'enable_cors', 'idle_writer_timeout', 'max_chunk_size', 'max_message_size' ]:
            if module.params[key] is not None:
                configuration[key] = module.params[key]
    elif input_type == "syslog":
        for key in [ 'bind_address', 'port', 'allow_override_date', 'expand_structured_data', 'force_rdns', \
                 'number_worker_threads', 'override_source', 'recv_buffer_size', 'store_full_message', \
                 'tcp_keepalive', 'tls_enable', 'tls_cert_file', 'tls_key_file', 'tls_key_password', \
                 'tls_client_auth', 'tls_client_auth_cert_file', 'use_null_delimiter' ]:
            if module.params[key] is not None:
                configuration[key] = module.params[key]

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

    return info['status'], info['msg'], content, base_url

def get_token(module, endpoint, username, password, allow_http):

    headers = '{ "Content-Type": "application/json", "X-Requested-By": "Graylog API", "Accept": "application/json" }'

    url = endpoint + "/api/system/sessions"

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
            graylog_fqdn=dict(type='str'),
            graylog_port=dict(type='str'),
            graylog_user=dict(type='str'),
            graylog_password=dict(type='str', no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            allow_http=dict(type='bool', required=False, default=False),
            action=dict(type='str', required=False, default='create',
                        choices=[ 'create', 'update' ]),
            force=dict(type='bool', required=False, default=False),
            log_format=dict(type='str', required=True, default='UDP',
                                choices=['GELF', 'Syslog', 'Cloudtrail', 'Cloudwatch']),
            input_protocol=dict(type='str', required=True, default='UDP',
                        choices=[ 'UDP', 'TCP', 'HTTP' ]),
            title=dict(type='str', required=True ),
            input_id=dict(type='str', required=False),
            global_input=dict(type='bool', required=False, default=True),
            node=dict(type='str', required=False),
            bind_address=dict(type='str', required=False, default='0.0.0.0'),
            port=dict(type='int', required=False, default=12201),
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
            max_message_size=dict(type='int', required=False, default=2097152)
        )
    )

    graylog_fqdn = module.params['graylog_fqdn']
    graylog_port = module.params['graylog_port']
    graylog_user = module.params['graylog_user']
    graylog_password = module.params['graylog_password']
    allow_http = module.params['allow_http']

    if allow_http == True:
      endpoint = "http://" + graylog_fqdn + ":" + graylog_port
    else:
      endpoint = "https://" + graylog_fqdn + ":" + graylog_port

    # Build full name of input type
    if log_format == "GELF":
        if module.params['input_protocol'] == "TCP":
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.tcp.GELFTCPInput"
        elif module.params['input_protocol'] == "UDP":
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.udp.GELFUDPInput"
        else:
            module.params['input_protocol'] = "org.graylog2.inputs.gelf.http.GELFHttpInput"
    elif log_format == "Syslog":
        #TODO: from syslog input, need to incorporate into above
        if module.params['input_protocol'] == "UDP":
            module.params['input_protocol'] = "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
        else:
            module.params['input_protocol'] = "org.graylog2.inputs.syslog.tcp.SyslogTCPInput"

    base_url = endpoint + "/api/system/inputs"

    api_token = get_token(module, endpoint, graylog_user, graylog_password, allow_http)
    headers = '{ "Content-Type": "application/json", \
                 "X-Requested-By": "Graylog API", \
                 "Accept": "application/json", \
                 "Authorization": "Basic ' + api_token.decode() + '" }'

    # create the input if one with same title does not exist
    status, message, content, url = create_input(module, base_url, headers)

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
