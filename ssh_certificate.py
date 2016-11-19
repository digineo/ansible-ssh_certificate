# This is a action plugin for Ansible 2.0
# Put it in your action_plugins folder.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import re
from datetime import datetime, timedelta
import subprocess
import tempfile
import base64
from struct import unpack

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):
        ''' handler for file transfer operations '''
        if task_vars is None:
            task_vars = dict()

        result   = super(ActionModule, self).run(tmp, task_vars)

        ca_key   = self._task.args.get('ca_key')  # local path
        pub_key  = self._task.args.get('pub_key') # remote path
        hostname = self._task.args.get('hostname', task_vars['inventory_hostname'])
        validity = self._task.args.get('validity', "52w")

        if ca_key is None:
            result['failed'] = True
            result['msg'] = "ca_key is required"
            return result

        if not os.path.exists(ca_key):
            result['failed'] = True
            result['msg'] = "%s does not exist" % ca_key
            return result

        if pub_key is None:
            result['failed'] = True
            result['msg'] = "pub_key is required"
            return result

        if hostname is None or hostname == "":
            result['failed'] = True
            result['msg'] = "hostname is required"
            return result

        remote_pub  = pub_key
        remote_cert = pub_key.replace(".pub","-cert.pub")
        refresh     = True

        try:
            # Download existing certificate
            _, tmp_path = tempfile.mkstemp()
            self._connection.fetch_file(remote_cert, tmp_path)

            # Parse certificate
            with open(tmp_path,'r') as f:
                decoded = decodeCert(f.read().split(" ")[1])
                refresh = datetime.utcfromtimestamp(decoded["valid before"]) < datetime.now() + timedelta(days=30)

        except AnsibleError:
            # Certificate does not exist (yet)
            pass
        finally:
            os.remove(tmp_path)

        if refresh:
            # Create a tempfile
            _, tmp_path = tempfile.mkstemp()
            tmp_cert    = tmp_path+"-cert.pub"

            # download pubkey
            self._connection.fetch_file(remote_pub, tmp_path)

            # Create certificate
            subprocess.check_output(["ssh-keygen", "-s", ca_key, "-h", "-n", hostname, "-V", ("+%d" % validity), "-I", ("%s-key" % hostname), tmp_path])

            # upload certificate
            res = self._connection.put_file(tmp_cert, remote_cert)

            result["changed"] = True

            os.remove(tmp_path)
            os.remove(tmp_cert)

        return result


def decodeCert(base64encoded):
    certType, bin = decodeString(base64.b64decode(base64encoded))

    h = {}
    for typ, key in formats[certType]:
        val, bin = typ(bin)
        h[key] = val
    return h


def decodeUint32(value):
    return unpack('>I', value[:4])[0], value[4:]

def decodeUint64(value):
    return unpack('>Q', value[:8])[0], value[8:]

def decodeMpint(value):
    size = unpack('>I', value[:4])[0]+4
    return None, value[size:]

def decodeString(value):
    size = unpack('>I', value[:4])[0]+4
    return value[4:size], value[size:]

def decodeList(value):
    joined, remaining = decodeString(value)
    list = []
    while len(joined) > 0:
        elem, joined = decodeString(joined)
        list.append(elem)
    return list, remaining

rsaFormat = [
    (decodeString, "nonce"),
    (decodeMpint,  "e"),
    (decodeMpint,  "n"),
    (decodeUint64, "serial"),
    (decodeUint32, "type"),
    (decodeString, "key id"),
    (decodeString, "valid principals"),
    (decodeUint64, "valid after"),
    (decodeUint64, "valid before"),
    (decodeString, "critical options"),
    (decodeString, "extensions"),
    (decodeString, "reserved"),
    (decodeString, "signature key"),
    (decodeString, "signature"),
]

dsaFormat = [
    (decodeString, ),
    (decodeString, "nonce"),
    (decodeMpint,  "p"),
    (decodeMpint,  "q"),
    (decodeMpint,  "g"),
    (decodeMpint,  "y"),
    (decodeUint64, "serial"),
    (decodeUint32, "type"),
    (decodeString, "key id"),
    (decodeString, "valid principals"),
    (decodeUint64, "valid after"),
    (decodeUint64, "valid before"),
    (decodeString, "critical options"),
    (decodeString, "extensions"),
    (decodeString, "reserved"),
    (decodeString, "signature key"),
    (decodeString, "signature"),
]

ecdsaFormat = [
    (decodeString, "nonce"),
    (decodeString, "curve"),
    (decodeString, "public_key"),
    (decodeUint64, "serial"),
    (decodeUint32, "type"),
    (decodeString, "key id"),
    (decodeString, "valid principals"),
    (decodeUint64, "valid after"),
    (decodeUint64, "valid before"),
    (decodeString, "critical options"),
    (decodeString, "extensions"),
    (decodeString, "reserved"),
    (decodeString, "signature key"),
    (decodeString, "signature"),
]

ed25519Format = [
    (decodeString, "nonce"),
    (decodeString, "pk"),
    (decodeUint64, "serial"),
    (decodeUint32, "type"),
    (decodeString, "key id"),
    (decodeList,   "valid principals"),
    (decodeUint64, "valid after"),
    (decodeUint64, "valid before"),
    (decodeString, "critical options"),
    (decodeString, "extensions"),
    (decodeString, "reserved"),
    (decodeString, "signature key"),
    (decodeString, "signature"),
]

formats = {
    "ssh-rsa-cert-v01@openssh.com":        rsaFormat,
    "ssh-dss-cert-v01@openssh.com":        dsaFormat,
    "ecdsa-sha2-nistp256-v01@openssh.com": ecdsaFormat,
    "ecdsa-sha2-nistp384-v01@openssh.com": ecdsaFormat,
    "ecdsa-sha2-nistp521-v01@openssh.com": ecdsaFormat,
    "ssh-ed25519-cert-v01@openssh.com":    ed25519Format,
}
