#!/usr/bin/python 
# -*- coding: utf-8 -*-

# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: setup
version_added: historical
short_description: Gathers facts about remote hosts
options:
    filter:
        version_added: "1.1"
        description:
            - if supplied, only return facts that match this shell-style (fnmatch) wildcard.
        required: false
        default: '*'
    fact_path:
        version_added: "1.3"
        description:
            - path used for local ansible facts (*.fact) - files in this dir
              will be run (if executable) and their results be added to ansible_local facts
              if a file is not executable it is read.
              File/results format can be json or ini-format
        required: false
        default: '/etc/ansible/facts.d'
description:
     - This module is automatically called by playbooks to gather useful
       variables about remote hosts that can be used in playbooks. It can also be
       executed directly by C(/usr/bin/ansible) to check what variables are
       available to a host. Ansible provides many I(facts) about the system,
       automatically.
notes:
    - More ansible facts will be added with successive releases. If I(facter) or
      I(ohai) are installed, variables from these programs will also be snapshotted
      into the JSON file for usage in templating. These variables are prefixed
      with C(facter_) and C(ohai_) so it's easy to tell their source. All variables are
      bubbled up to the caller. Using the ansible facts and choosing to not
      install I(facter) and I(ohai) means you can avoid Ruby-dependencies on your
      remote systems. (See also M(facter) and M(ohai).)
    - The filter option filters only the first level subkey below ansible_facts.
    - If the target host is Windows, you will not currently have the ability to use
      C(fact_path) or C(filter) as this is provided by a simpler implementation of the module.
      Different facts are returned for Windows hosts.
author: Michael DeHaan
'''

EXAMPLES = """
# Display facts from all hosts and store them indexed by I(hostname) at C(/tmp/facts).
ansible all -m setup --tree /tmp/facts

# Display only facts regarding memory found by ansible on all hosts and output them.
ansible all -m setup -a 'filter=ansible_*_mb'

# Display only facts returned by facter.
ansible all -m setup -a 'filter=facter_*'

# Display only facts about certain interfaces.
ansible all -m setup -a 'filter=ansible_eth[0-2]'
"""


def run_setup(module):

    #setup_options = dict(module_setup=True)
    setup_options = dict()
    facts = ansible_facts(module)

    for (k, v) in facts.items():
        setup_options["%s" % k.replace('-', '_')] = v

    setup_result = {}

    for (k,v) in setup_options.items():
        if module.params['filter'] == '*' or fnmatch.fnmatch(k, module.params['filter']):
            #setup_result['ansible_facts'][k] = v
	    setup_result[k] = v

    return setup_result

def main():
    global module
    module = AnsibleModule(
        argument_spec = dict(
            filter=dict(default="*", required=False),
            fact_path=dict(default='/etc/ansible/facts.d', required=False),
        ),
        supports_check_mode = True,
    )
    data = run_setup(module)
    module.exit_json(**data)

def get_result():
    global module
    module = AnsibleModule(
        argument_spec = dict(
            filter=dict(default="*", required=False),
            fact_path=dict(default='/etc/ansible/facts.d', required=False),
        ),
        supports_check_mode = True,
    )
    return run_setup(module)

# import module snippets

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
# 
# Copyright (c), Michael DeHaan <michael.dehaan@gmail.com>, 2012-2013
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright 
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, 
#      this list of conditions and the following disclaimer in the documentation 
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# == BEGIN DYNAMICALLY INSERTED CODE ==

ANSIBLE_VERSION = '1.8.2'

MODULE_ARGS = ''
MODULE_COMPLEX_ARGS = '{}'

BOOLEANS_TRUE = ['yes', 'on', '1', 'true', 1]
BOOLEANS_FALSE = ['no', 'off', '0', 'false', 0]
BOOLEANS = BOOLEANS_TRUE + BOOLEANS_FALSE

# ansible modules can be written in any language.  To simplify
# development of Python modules, the functions available here
# can be inserted in any module source automatically by including
# #<<INCLUDE_ANSIBLE_MODULE_COMMON>> on a blank line by itself inside
# of an ansible module. The source of this common code lives
# in lib/ansible/module_common.py

import locale
import os
import re
import pipes
import shlex
import subprocess
import sys
import syslog
import types
import time
import select
import shutil
import stat
import tempfile
import traceback
import grp
import pwd
import platform
import errno
import tempfile

try:
    import json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        sys.stderr.write('Error: ansible requires a json module, none found!')
        sys.exit(1)
    except SyntaxError:
        sys.stderr.write('SyntaxError: probably due to json and python being for different versions')
        sys.exit(1)

HAVE_SELINUX=False
try:
    import selinux
    HAVE_SELINUX=True
except ImportError:
    pass

HAVE_HASHLIB=False
try:
    from hashlib import sha1 as _sha1
    HAVE_HASHLIB=True
except ImportError:
    from sha import sha as _sha1

try:
    from hashlib import md5 as _md5
except ImportError:
    try:
        from md5 import md5 as _md5
    except ImportError:
        # MD5 unavailable.  Possibly FIPS mode
        _md5 = None

try:
    from hashlib import sha256 as _sha256
except ImportError:
    pass

try:
    from systemd import journal
    has_journal = True
except ImportError:
    import syslog
    has_journal = False

try:
    from ast import literal_eval as _literal_eval
except ImportError:
    # a replacement for literal_eval that works with python 2.4. from: 
    # https://mail.python.org/pipermail/python-list/2009-September/551880.html
    # which is essentially a cut/past from an earlier (2.6) version of python's
    # ast.py
    from compiler import parse
    from compiler.ast import *
    def _literal_eval(node_or_string):
        """
        Safely evaluate an expression node or a string containing a Python
        expression.  The string or node provided may only consist of the  following
        Python literal structures: strings, numbers, tuples, lists, dicts,  booleans,
        and None.
        """
        _safe_names = {'None': None, 'True': True, 'False': False}
        if isinstance(node_or_string, basestring):
            node_or_string = parse(node_or_string, mode='eval')
        if isinstance(node_or_string, Expression):
            node_or_string = node_or_string.node
        def _convert(node):
            if isinstance(node, Const) and isinstance(node.value, (basestring, int, float, long, complex)):
                 return node.value
            elif isinstance(node, Tuple):
                return tuple(map(_convert, node.nodes))
            elif isinstance(node, List):
                return list(map(_convert, node.nodes))
            elif isinstance(node, Dict):
                return dict((_convert(k), _convert(v)) for k, v in node.items)
            elif isinstance(node, Name):
                if node.name in _safe_names:
                    return _safe_names[node.name]
            elif isinstance(node, UnarySub):
                return -_convert(node.expr)
            raise ValueError('malformed string')
        return _convert(node_or_string)

FILE_COMMON_ARGUMENTS=dict(
    src = dict(),
    mode = dict(),
    owner = dict(),
    group = dict(),
    seuser = dict(),
    serole = dict(),
    selevel = dict(),
    setype = dict(),
    follow = dict(type='bool', default=False),
    # not taken by the file module, but other modules call file so it must ignore them.
    content = dict(no_log=True),
    backup = dict(),
    force = dict(),
    remote_src = dict(), # used by assemble
    regexp = dict(), # used by assemble
    delimiter = dict(), # used by assemble
    directory_mode = dict(), # used by copy
)


def get_platform():
    ''' what's the platform?  example: Linux is a platform. '''
    return platform.system()

def get_distribution():
    ''' return the distribution name '''
    if platform.system() == 'Linux':
        try:
            distribution = platform.linux_distribution()[0].capitalize()
            if not distribution and os.path.isfile('/etc/system-release'):
                distribution = platform.linux_distribution(supported_dists=['system'])[0].capitalize()
                if 'Amazon' in distribution:
                    distribution = 'Amazon'
                else:
                    distribution = 'OtherLinux'
        except:
            # FIXME: MethodMissing, I assume?
            distribution = platform.dist()[0].capitalize()
    else:
        distribution = None
    return distribution

def get_distribution_version():
    ''' return the distribution version '''
    if platform.system() == 'Linux':
        try:
            distribution_version = platform.linux_distribution()[1]
            if not distribution_version and os.path.isfile('/etc/system-release'):
                distribution_version = platform.linux_distribution(supported_dists=['system'])[1]
        except:
            # FIXME: MethodMissing, I assume?
            distribution_version = platform.dist()[1]
    else:
        distribution_version = None
    return distribution_version

def load_platform_subclass(cls, *args, **kwargs):
    '''
    used by modules like User to have different implementations based on detected platform.  See User
    module for an example.
    '''

    this_platform = get_platform()
    distribution = get_distribution()
    subclass = None

    # get the most specific superclass for this platform
    if distribution is not None:
        for sc in cls.__subclasses__():
            if sc.distribution is not None and sc.distribution == distribution and sc.platform == this_platform:
                subclass = sc
    if subclass is None:
        for sc in cls.__subclasses__():
            if sc.platform == this_platform and sc.distribution is None:
                subclass = sc
    if subclass is None:
        subclass = cls

    return super(cls, subclass).__new__(subclass)


def json_dict_unicode_to_bytes(d):
    ''' Recursively convert dict keys and values to byte str

        Specialized for json return because this only handles, lists, tuples,
        and dict container types (the containers that the json module returns)
    '''

    if isinstance(d, unicode):
        return d.encode('utf-8')
    elif isinstance(d, dict):
        return dict(map(json_dict_unicode_to_bytes, d.iteritems()))
    elif isinstance(d, list):
        return list(map(json_dict_unicode_to_bytes, d))
    elif isinstance(d, tuple):
        return tuple(map(json_dict_unicode_to_bytes, d))
    else:
        return d


class AnsibleModule(object):

    def __init__(self, argument_spec, bypass_checks=False, no_log=False,
        check_invalid_arguments=True, mutually_exclusive=None, required_together=None,
        required_one_of=None, add_file_common_args=False, supports_check_mode=False):

        '''
        common code for quickly building an ansible module in Python
        (although you can write modules in anything that can return JSON)
        see library/* for examples
        '''

        self.argument_spec = argument_spec
        self.supports_check_mode = supports_check_mode
        self.check_mode = False
        self.no_log = no_log
        self.cleanup_files = []
        
        self.aliases = {}
        
        if add_file_common_args:
            for k, v in FILE_COMMON_ARGUMENTS.iteritems():
                if k not in self.argument_spec:
                    self.argument_spec[k] = v

        # check the locale as set by the current environment, and
        # reset to LANG=C if it's an invalid/unavailable locale
        self._check_locale()

        (self.params, self.args) = self._load_params()

        self._legal_inputs = ['CHECKMODE', 'NO_LOG']
        
        self.aliases = self._handle_aliases()

        if check_invalid_arguments:
            self._check_invalid_arguments()
        self._check_for_check_mode()
        self._check_for_no_log()

        # check exclusive early 
        if not bypass_checks:
            self._check_mutually_exclusive(mutually_exclusive)

        self._set_defaults(pre=True)

        if not bypass_checks:
            self._check_required_arguments()
            self._check_argument_values()
            self._check_argument_types()
            self._check_required_together(required_together)
            self._check_required_one_of(required_one_of)

        self._set_defaults(pre=False)
        if not self.no_log:
            self._log_invocation()

        # finally, make sure we're in a sane working dir
        self._set_cwd()

    def load_file_common_arguments(self, params):
        '''
        many modules deal with files, this encapsulates common
        options that the file module accepts such that it is directly
        available to all modules and they can share code.
        '''

        path = params.get('path', params.get('dest', None))
        if path is None:
            return {}
        else:
            path = os.path.expanduser(path)

        # if the path is a symlink, and we're following links, get
        # the target of the link instead for testing
        if params.get('follow', False) and os.path.islink(path):
            path = os.path.realpath(path)

        mode   = params.get('mode', None)
        owner  = params.get('owner', None)
        group  = params.get('group', None)

        # selinux related options
        seuser    = params.get('seuser', None)
        serole    = params.get('serole', None)
        setype    = params.get('setype', None)
        selevel   = params.get('selevel', None)
        secontext = [seuser, serole, setype]

        if self.selinux_mls_enabled():
            secontext.append(selevel)

        default_secontext = self.selinux_default_context(path)
        for i in range(len(default_secontext)):
            if i is not None and secontext[i] == '_default':
                secontext[i] = default_secontext[i]

        return dict(
            path=path, mode=mode, owner=owner, group=group,
            seuser=seuser, serole=serole, setype=setype,
            selevel=selevel, secontext=secontext,
        )


    # Detect whether using selinux that is MLS-aware.
    # While this means you can set the level/range with
    # selinux.lsetfilecon(), it may or may not mean that you
    # will get the selevel as part of the context returned
    # by selinux.lgetfilecon().

    def selinux_mls_enabled(self):
        if not HAVE_SELINUX:
            return False
        if selinux.is_selinux_mls_enabled() == 1:
            return True
        else:
            return False

    def selinux_enabled(self):
        if not HAVE_SELINUX:
            seenabled = self.get_bin_path('selinuxenabled')
            if seenabled is not None:
                (rc,out,err) = self.run_command(seenabled)
                if rc == 0:
                    self.fail_json(msg="Aborting, target uses selinux but python bindings (libselinux-python) aren't installed!")
            return False
        if selinux.is_selinux_enabled() == 1:
            return True
        else:
            return False

    # Determine whether we need a placeholder for selevel/mls
    def selinux_initial_context(self):
        context = [None, None, None]
        if self.selinux_mls_enabled():
            context.append(None)
        return context

    def _to_filesystem_str(self, path):
        '''Returns filesystem path as a str, if it wasn't already.

        Used in selinux interactions because it cannot accept unicode
        instances, and specifying complex args in a playbook leaves
        you with unicode instances.  This method currently assumes
        that your filesystem encoding is UTF-8.

        '''
        if isinstance(path, unicode):
            path = path.encode("utf-8")
        return path

    # If selinux fails to find a default, return an array of None
    def selinux_default_context(self, path, mode=0):
        context = self.selinux_initial_context()
        if not HAVE_SELINUX or not self.selinux_enabled():
            return context
        try:
            ret = selinux.matchpathcon(self._to_filesystem_str(path), mode)
        except OSError:
            return context
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context

    def selinux_context(self, path):
        context = self.selinux_initial_context()
        if not HAVE_SELINUX or not self.selinux_enabled():
            return context
        try:
            ret = selinux.lgetfilecon_raw(self._to_filesystem_str(path))
        except OSError, e:
            if e.errno == errno.ENOENT:
                self.fail_json(path=path, msg='path %s does not exist' % path)
            else:
                self.fail_json(path=path, msg='failed to retrieve selinux context')
        if ret[0] == -1:
            return context
        # Limit split to 4 because the selevel, the last in the list,
        # may contain ':' characters
        context = ret[1].split(':', 3)
        return context

    def user_and_group(self, filename):
        filename = os.path.expanduser(filename)
        st = os.lstat(filename)
        uid = st.st_uid
        gid = st.st_gid
        return (uid, gid)

    def find_mount_point(self, path):
        path = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
        while not os.path.ismount(path):
            path = os.path.dirname(path)
        return path

    def is_nfs_path(self, path):
        """
        Returns a tuple containing (True, selinux_context) if the given path
        is on a NFS mount point, otherwise the return will be (False, None).
        """
        try:
            f = open('/proc/mounts', 'r')
            mount_data = f.readlines()
            f.close()
        except:
            return (False, None)
        path_mount_point = self.find_mount_point(path)
        for line in mount_data:
            (device, mount_point, fstype, options, rest) = line.split(' ', 4)
            if path_mount_point == mount_point and 'nfs' in fstype:
                nfs_context = self.selinux_context(path_mount_point)
                return (True, nfs_context)
        return (False, None)

    def set_default_selinux_context(self, path, changed):
        if not HAVE_SELINUX or not self.selinux_enabled():
            return changed
        context = self.selinux_default_context(path)
        return self.set_context_if_different(path, context, False)

    def set_context_if_different(self, path, context, changed):

        if not HAVE_SELINUX or not self.selinux_enabled():
            return changed
        cur_context = self.selinux_context(path)
        new_context = list(cur_context)
        # Iterate over the current context instead of the
        # argument context, which may have selevel.

        (is_nfs, nfs_context) = self.is_nfs_path(path)
        if is_nfs:
            new_context = nfs_context
        else:
            for i in range(len(cur_context)):
                if len(context) > i:
                    if context[i] is not None and context[i] != cur_context[i]:
                        new_context[i] = context[i]
                    if context[i] is None:
                        new_context[i] = cur_context[i]

        if cur_context != new_context:
            try:
                if self.check_mode:
                    return True
                rc = selinux.lsetfilecon(self._to_filesystem_str(path),
                                         str(':'.join(new_context)))
            except OSError:
                self.fail_json(path=path, msg='invalid selinux context', new_context=new_context, cur_context=cur_context, input_was=context)
            if rc != 0:
                self.fail_json(path=path, msg='set selinux context failed')
            changed = True
        return changed

    def set_owner_if_different(self, path, owner, changed):
        path = os.path.expanduser(path)
        if owner is None:
            return changed
        orig_uid, orig_gid = self.user_and_group(path)
        try:
            uid = int(owner)
        except ValueError:
            try:
                uid = pwd.getpwnam(owner).pw_uid
            except KeyError:
                self.fail_json(path=path, msg='chown failed: failed to look up user %s' % owner)
        if orig_uid != uid:
            if self.check_mode:
                return True
            try:
                os.lchown(path, uid, -1)
            except OSError:
                self.fail_json(path=path, msg='chown failed')
            changed = True
        return changed

    def set_group_if_different(self, path, group, changed):
        path = os.path.expanduser(path)
        if group is None:
            return changed
        orig_uid, orig_gid = self.user_and_group(path)
        try:
            gid = int(group)
        except ValueError:
            try:
                gid = grp.getgrnam(group).gr_gid
            except KeyError:
                self.fail_json(path=path, msg='chgrp failed: failed to look up group %s' % group)
        if orig_gid != gid:
            if self.check_mode:
                return True
            try:
                os.lchown(path, -1, gid)
            except OSError:
                self.fail_json(path=path, msg='chgrp failed')
            changed = True
        return changed

    def set_mode_if_different(self, path, mode, changed):
        path = os.path.expanduser(path)
        path_stat = os.lstat(path)

        if mode is None:
            return changed

        if not isinstance(mode, int):
            try:
                mode = int(mode, 8)
            except Exception:
                try:
                    mode = self._symbolic_mode_to_octal(path_stat, mode)
                except Exception, e:
                    self.fail_json(path=path,
                                   msg="mode must be in octal or symbolic form",
                                   details=str(e))

        prev_mode = stat.S_IMODE(path_stat.st_mode)

        if prev_mode != mode:
            if self.check_mode:
                return True
            # FIXME: comparison against string above will cause this to be executed
            # every time
            try:
                if 'lchmod' in dir(os):
                    os.lchmod(path, mode)
                else:
                    os.chmod(path, mode)
            except OSError, e:
                if os.path.islink(path) and e.errno == errno.EPERM:  # Can't set mode on symbolic links
                    pass
                elif e.errno == errno.ENOENT: # Can't set mode on broken symbolic links
                    pass
                else:
                    raise e
            except Exception, e:
                self.fail_json(path=path, msg='chmod failed', details=str(e))

            path_stat = os.lstat(path)
            new_mode = stat.S_IMODE(path_stat.st_mode)

            if new_mode != prev_mode:
                changed = True
        return changed

    def _symbolic_mode_to_octal(self, path_stat, symbolic_mode):
        new_mode = stat.S_IMODE(path_stat.st_mode)

        mode_re = re.compile(r'^(?P<users>[ugoa]+)(?P<operator>[-+=])(?P<perms>[rwxXst]*|[ugo])$')
        for mode in symbolic_mode.split(','):
            match = mode_re.match(mode)
            if match:
                users = match.group('users')
                operator = match.group('operator')
                perms = match.group('perms')

                if users == 'a': users = 'ugo'

                for user in users:
                    mode_to_apply = self._get_octal_mode_from_symbolic_perms(path_stat, user, perms)
                    new_mode = self._apply_operation_to_mode(user, operator, mode_to_apply, new_mode)
            else:
                raise ValueError("bad symbolic permission for mode: %s" % mode)
        return new_mode
    
    def _apply_operation_to_mode(self, user, operator, mode_to_apply, current_mode):
        if operator  ==  '=':
            if user == 'u': mask = stat.S_IRWXU | stat.S_ISUID
            elif user == 'g': mask = stat.S_IRWXG | stat.S_ISGID
            elif user == 'o': mask = stat.S_IRWXO | stat.S_ISVTX
            
            # mask out u, g, or o permissions from current_mode and apply new permissions   
            inverse_mask = mask ^ 07777
            new_mode = (current_mode & inverse_mask) | mode_to_apply
        elif operator == '+':
            new_mode = current_mode | mode_to_apply
        elif operator == '-':
            new_mode = current_mode - (current_mode & mode_to_apply)
        return new_mode
        
    def _get_octal_mode_from_symbolic_perms(self, path_stat, user, perms):
        prev_mode = stat.S_IMODE(path_stat.st_mode)
        
        is_directory = stat.S_ISDIR(path_stat.st_mode)
        has_x_permissions = (prev_mode & 00111) > 0
        apply_X_permission = is_directory or has_x_permissions

        # Permission bits constants documented at:
        # http://docs.python.org/2/library/stat.html#stat.S_ISUID
        if apply_X_permission:
            X_perms = {
                'u': {'X': stat.S_IXUSR},
                'g': {'X': stat.S_IXGRP},
                'o': {'X': stat.S_IXOTH}
            }
        else:
            X_perms = {
                'u': {'X': 0},
                'g': {'X': 0},
                'o': {'X': 0}
            }

        user_perms_to_modes = {
            'u': {
                'r': stat.S_IRUSR,
                'w': stat.S_IWUSR,
                'x': stat.S_IXUSR,
                's': stat.S_ISUID,
                't': 0,
                'u': prev_mode & stat.S_IRWXU,
                'g': (prev_mode & stat.S_IRWXG) << 3,
                'o': (prev_mode & stat.S_IRWXO) << 6 },
            'g': {
                'r': stat.S_IRGRP,
                'w': stat.S_IWGRP,
                'x': stat.S_IXGRP,
                's': stat.S_ISGID,
                't': 0,
                'u': (prev_mode & stat.S_IRWXU) >> 3,
                'g': prev_mode & stat.S_IRWXG,
                'o': (prev_mode & stat.S_IRWXO) << 3 },
            'o': {
                'r': stat.S_IROTH,
                'w': stat.S_IWOTH,
                'x': stat.S_IXOTH,
                's': 0,
                't': stat.S_ISVTX,
                'u': (prev_mode & stat.S_IRWXU) >> 6,
                'g': (prev_mode & stat.S_IRWXG) >> 3,
                'o': prev_mode & stat.S_IRWXO }
        }

        # Insert X_perms into user_perms_to_modes
        for key, value in X_perms.items():
            user_perms_to_modes[key].update(value)

        or_reduce = lambda mode, perm: mode | user_perms_to_modes[user][perm]
        return reduce(or_reduce, perms, 0)

    def set_fs_attributes_if_different(self, file_args, changed):
        # set modes owners and context as needed
        changed = self.set_context_if_different(
            file_args['path'], file_args['secontext'], changed
        )
        changed = self.set_owner_if_different(
            file_args['path'], file_args['owner'], changed
        )
        changed = self.set_group_if_different(
            file_args['path'], file_args['group'], changed
        )
        changed = self.set_mode_if_different(
            file_args['path'], file_args['mode'], changed
        )
        return changed

    def set_directory_attributes_if_different(self, file_args, changed):
        return self.set_fs_attributes_if_different(file_args, changed)

    def set_file_attributes_if_different(self, file_args, changed):
        return self.set_fs_attributes_if_different(file_args, changed)

    def add_path_info(self, kwargs):
        '''
        for results that are files, supplement the info about the file
        in the return path with stats about the file path.
        '''

        path = kwargs.get('path', kwargs.get('dest', None))
        if path is None:
            return kwargs
        if os.path.exists(path):
            (uid, gid) = self.user_and_group(path)
            kwargs['uid'] = uid
            kwargs['gid'] = gid
            try:
                user = pwd.getpwuid(uid)[0]
            except KeyError:
                user = str(uid)
            try:
                group = grp.getgrgid(gid)[0]
            except KeyError:
                group = str(gid)
            kwargs['owner'] = user
            kwargs['group'] = group
            st = os.lstat(path)
            kwargs['mode']  = oct(stat.S_IMODE(st[stat.ST_MODE]))
            # secontext not yet supported
            if os.path.islink(path):
                kwargs['state'] = 'link'
            elif os.path.isdir(path):
                kwargs['state'] = 'directory'
            elif os.stat(path).st_nlink > 1:
                kwargs['state'] = 'hard'
            else:
                kwargs['state'] = 'file'
            if HAVE_SELINUX and self.selinux_enabled():
                kwargs['secontext'] = ':'.join(self.selinux_context(path))
            kwargs['size'] = st[stat.ST_SIZE]
        else:
            kwargs['state'] = 'absent'
        return kwargs

    def _check_locale(self):
        '''
        Uses the locale module to test the currently set locale
        (per the LANG and LC_CTYPE environment settings)
        '''
        try:
            # setting the locale to '' uses the default locale
            # as it would be returned by locale.getdefaultlocale()
            locale.setlocale(locale.LC_ALL, '')
        except locale.Error, e:
            # fallback to the 'C' locale, which may cause unicode
            # issues but is preferable to simply failing because
            # of an unknown locale
            locale.setlocale(locale.LC_ALL, 'C')
            os.environ['LANG']     = 'C'
            os.environ['LC_CTYPE'] = 'C'
        except Exception, e:
            self.fail_json(msg="An unknown error was encountered while attempting to validate the locale: %s" % e)

    def _handle_aliases(self):
        aliases_results = {} #alias:canon
        for (k,v) in self.argument_spec.iteritems():
            self._legal_inputs.append(k)
            aliases = v.get('aliases', None)
            default = v.get('default', None)
            required = v.get('required', False)
            if default is not None and required:
                # not alias specific but this is a good place to check this
                self.fail_json(msg="internal error: required and default are mutually exclusive for %s" % k)
            if aliases is None:
                continue
            if type(aliases) != list:
                self.fail_json(msg='internal error: aliases must be a list')
            for alias in aliases:
                self._legal_inputs.append(alias)
                aliases_results[alias] = k
                if alias in self.params:
                    self.params[k] = self.params[alias]
        
        return aliases_results

    def _check_for_check_mode(self):
        for (k,v) in self.params.iteritems():
            if k == 'CHECKMODE':
                if not self.supports_check_mode:
                    self.exit_json(skipped=True, msg="remote module does not support check mode")
                if self.supports_check_mode:
                    self.check_mode = True

    def _check_for_no_log(self):
        for (k,v) in self.params.iteritems():
            if k == 'NO_LOG':
                self.no_log = self.boolean(v)

    def _check_invalid_arguments(self):
        for (k,v) in self.params.iteritems():
            # these should be in legal inputs already
            #if k in ('CHECKMODE', 'NO_LOG'):
            #    continue
            if k not in self._legal_inputs:
                self.fail_json(msg="unsupported parameter for module: %s" % k)

    def _count_terms(self, check):
        count = 0
        for term in check:
            if term in self.params:
                count += 1
        return count

    def _check_mutually_exclusive(self, spec):
        if spec is None:
            return
        for check in spec:
            count = self._count_terms(check)
            if count > 1:
                self.fail_json(msg="parameters are mutually exclusive: %s" % check)

    def _check_required_one_of(self, spec):
        if spec is None:
            return
        for check in spec:
            count = self._count_terms(check)
            if count == 0:
                self.fail_json(msg="one of the following is required: %s" % ','.join(check))

    def _check_required_together(self, spec):
        if spec is None:
            return
        for check in spec:
            counts = [ self._count_terms([field]) for field in check ]
            non_zero = [ c for c in counts if c > 0 ]
            if len(non_zero) > 0:
                if 0 in counts:
                    self.fail_json(msg="parameters are required together: %s" % check)

    def _check_required_arguments(self):
        ''' ensure all required arguments are present '''
        missing = []
        for (k,v) in self.argument_spec.iteritems():
            required = v.get('required', False)
            if required and k not in self.params:
                missing.append(k)
        if len(missing) > 0:
            self.fail_json(msg="missing required arguments: %s" % ",".join(missing))

    def _check_argument_values(self):
        ''' ensure all arguments have the requested values, and there are no stray arguments '''
        for (k,v) in self.argument_spec.iteritems():
            choices = v.get('choices',None)
            if choices is None:
                continue
            if type(choices) == list:
                if k in self.params:
                    if self.params[k] not in choices:
                        choices_str=",".join([str(c) for c in choices])
                        msg="value of %s must be one of: %s, got: %s" % (k, choices_str, self.params[k])
                        self.fail_json(msg=msg)
            else:
                self.fail_json(msg="internal error: do not know how to interpret argument_spec")

    def safe_eval(self, str, locals=None, include_exceptions=False):

        # do not allow method calls to modules
        if not isinstance(str, basestring):
            # already templated to a datastructure, perhaps?
            if include_exceptions:
                return (str, None)
            return str
        if re.search(r'\w\.\w+\(', str):
            if include_exceptions:
                return (str, None)
            return str
        # do not allow imports
        if re.search(r'import \w+', str):
            if include_exceptions:
                return (str, None)
            return str
        try:
            result = None
            if not locals:
                result = _literal_eval(str)
            else:
                result = _literal_eval(str, None, locals)
            if include_exceptions:
                return (result, None)
            else:
                return result
        except Exception, e:
            if include_exceptions:
                return (str, e)
            return str

    def _check_argument_types(self):
        ''' ensure all arguments have the requested type '''
        for (k, v) in self.argument_spec.iteritems():
            wanted = v.get('type', None)
            if wanted is None:
                continue
            if k not in self.params:
                continue

            value = self.params[k]
            is_invalid = False

            if wanted == 'str':
                if not isinstance(value, basestring):
                    self.params[k] = str(value)
            elif wanted == 'list':
                if not isinstance(value, list):
                    if isinstance(value, basestring):
                        self.params[k] = value.split(",")
                    elif isinstance(value, int) or isinstance(value, float):
                        self.params[k] = [ str(value) ]
                    else:
                        is_invalid = True
            elif wanted == 'dict':
                if not isinstance(value, dict):
                    if isinstance(value, basestring):
                        if value.startswith("{"):
                            try:
                                self.params[k] = json.loads(value)
                            except:
                                (result, exc) = self.safe_eval(value, dict(), include_exceptions=True)
                                if exc is not None:
                                    self.fail_json(msg="unable to evaluate dictionary for %s" % k)
                                self.params[k] = result
                        elif '=' in value:
                            self.params[k] = dict([x.strip().split("=", 1) for x in value.split(",")])
                        else:
                            self.fail_json(msg="dictionary requested, could not parse JSON or key=value")
                    else:
                        is_invalid = True
            elif wanted == 'bool':
                if not isinstance(value, bool):
                    if isinstance(value, basestring):
                        self.params[k] = self.boolean(value)
                    else:
                        is_invalid = True
            elif wanted == 'int':
                if not isinstance(value, int):
                    if isinstance(value, basestring):
                        self.params[k] = int(value)
                    else:
                        is_invalid = True
            elif wanted == 'float':
                if not isinstance(value, float):
                    if isinstance(value, basestring):
                        self.params[k] = float(value)
                    else:
                        is_invalid = True
            else:
                self.fail_json(msg="implementation error: unknown type %s requested for %s" % (wanted, k))

            if is_invalid:
                self.fail_json(msg="argument %s is of invalid type: %s, required: %s" % (k, type(value), wanted))

    def _set_defaults(self, pre=True):
        for (k,v) in self.argument_spec.iteritems():
            default = v.get('default', None)
            if pre == True:
                # this prevents setting defaults on required items
                if default is not None and k not in self.params:
                    self.params[k] = default
            else:
                # make sure things without a default still get set None
                if k not in self.params:
                    self.params[k] = default

    def _load_params(self):
        ''' read the input and return a dictionary and the arguments string '''
        args = MODULE_ARGS
        items   = shlex.split(args)
        params = {}
        for x in items:
            try:
                (k, v) = x.split("=",1)
            except Exception, e:
                self.fail_json(msg="this module requires key=value arguments (%s)" % (items))
            if k in params:
                self.fail_json(msg="duplicate parameter: %s (value=%s)" % (k, v))
            params[k] = v
        params2 = json_dict_unicode_to_bytes(json.loads(MODULE_COMPLEX_ARGS))
        params2.update(params)
        return (params2, args)

    def _heuristic_log_sanitize(self, data):
        ''' Remove strings that look like passwords from log messages '''
        # Currently filters:
        # user:pass@foo/whatever and http://username:pass@wherever/foo
        # This code has false positives and consumes parts of logs that are
        # not passwds

        # begin: start of a passwd containing string
        # end: end of a passwd containing string
        # sep: char between user and passwd
        # prev_begin: where in the overall string to start a search for
        #   a passwd
        # sep_search_end: where in the string to end a search for the sep
        output = []
        begin = len(data)
        prev_begin = begin
        sep = 1
        while sep:
            # Find the potential end of a passwd
            try:
                end = data.rindex('@', 0, begin)
            except ValueError:
                # No passwd in the rest of the data
                output.insert(0, data[0:begin])
                break

            # Search for the beginning of a passwd
            sep = None
            sep_search_end = end
            while not sep:
                # URL-style username+password
                try:
                    begin = data.rindex('://', 0, sep_search_end)
                except ValueError:
                    # No url style in the data, check for ssh style in the
                    # rest of the string
                    begin = 0
                # Search for separator
                try:
                    sep = data.index(':', begin + 3, end)
                except ValueError:
                    # No separator; choices:
                    if begin == 0:
                        # Searched the whole string so there's no password
                        # here.  Return the remaining data
                        output.insert(0, data[0:begin])
                        break
                    # Search for a different beginning of the password field.
                    sep_search_end = begin
                    continue
            if sep:
                # Password was found; remove it.
                output.insert(0, data[end:prev_begin])
                output.insert(0, '********')
                output.insert(0, data[begin:sep + 1])
                prev_begin = begin

        return ''.join(output)

    def _log_invocation(self):
        ''' log that ansible ran the module '''
        # TODO: generalize a separate log function and make log_invocation use it
        # Sanitize possible password argument when logging.
        log_args = dict()
        passwd_keys = ['password', 'login_password']

        for param in self.params:
            canon  = self.aliases.get(param, param)
            arg_opts = self.argument_spec.get(canon, {})
            no_log = arg_opts.get('no_log', False)

            if self.boolean(no_log):
                log_args[param] = 'NOT_LOGGING_PARAMETER'
            elif param in passwd_keys:
                log_args[param] = 'NOT_LOGGING_PASSWORD'
            else:
                param_val = self.params[param]
                if not isinstance(param_val, basestring):
                    param_val = str(param_val)
                elif isinstance(param_val, unicode):
                    param_val = param_val.encode('utf-8')
                log_args[param] = self._heuristic_log_sanitize(param_val)

        module = 'ansible-%s' % os.path.basename(__file__)
        msg = []
        for arg in log_args:
            arg_val = log_args[arg]
            if not isinstance(arg_val, basestring):
                arg_val = str(arg_val)
            elif isinstance(arg_val, unicode):
                arg_val = arg_val.encode('utf-8')
            msg.append('%s=%s ' % (arg, arg_val))
        if msg:
            msg = 'Invoked with %s' % ''.join(msg)
        else:
            msg = 'Invoked'

        # 6655 - allow for accented characters
        if isinstance(msg, unicode):
            # We should never get here as msg should be type str, not unicode
            msg = msg.encode('utf-8')

        if (has_journal):
            journal_args = ["MESSAGE=%s %s" % (module, msg)]
            journal_args.append("MODULE=%s" % os.path.basename(__file__))
            for arg in log_args:
                journal_args.append(arg.upper() + "=" + str(log_args[arg]))
            try:
                journal.sendv(*journal_args)
            except IOError, e:
                # fall back to syslog since logging to journal failed
                syslog.openlog(str(module), 0, syslog.LOG_USER)
                syslog.syslog(syslog.LOG_NOTICE, msg) #1
        else:
            syslog.openlog(str(module), 0, syslog.LOG_USER)
            syslog.syslog(syslog.LOG_NOTICE, msg) #2

    def _set_cwd(self):
        try:
            cwd = os.getcwd()
            if not os.access(cwd, os.F_OK|os.R_OK):
                raise
            return cwd
        except:
            # we don't have access to the cwd, probably because of sudo. 
            # Try and move to a neutral location to prevent errors
            for cwd in [os.path.expandvars('$HOME'), tempfile.gettempdir()]:
                try:
                    if os.access(cwd, os.F_OK|os.R_OK):
                        os.chdir(cwd)
                        return cwd
                except:
                    pass
        # we won't error here, as it may *not* be a problem, 
        # and we don't want to break modules unnecessarily
        return None    

    def get_bin_path(self, arg, required=False, opt_dirs=[]):
        '''
        find system executable in PATH.
        Optional arguments:
           - required:  if executable is not found and required is true, fail_json
           - opt_dirs:  optional list of directories to search in addition to PATH
        if found return full path; otherwise return None
        '''
        sbin_paths = ['/sbin', '/usr/sbin', '/usr/local/sbin']
        paths = []
        for d in opt_dirs:
            if d is not None and os.path.exists(d):
                paths.append(d)
        paths += os.environ.get('PATH', '').split(os.pathsep)
        bin_path = None
        # mangle PATH to include /sbin dirs
        for p in sbin_paths:
            if p not in paths and os.path.exists(p):
                paths.append(p)
        for d in paths:
            path = os.path.join(d, arg)
            if os.path.exists(path) and self.is_executable(path):
                bin_path = path
                break
        if required and bin_path is None:
            self.fail_json(msg='Failed to find required executable %s' % arg)
        return bin_path

    def boolean(self, arg):
        ''' return a bool for the arg '''
        if arg is None or type(arg) == bool:
            return arg
        if type(arg) in types.StringTypes:
            arg = arg.lower()
        if arg in BOOLEANS_TRUE:
            return True
        elif arg in BOOLEANS_FALSE:
            return False
        else:
            self.fail_json(msg='Boolean %s not in either boolean list' % arg)

    def jsonify(self, data):
        for encoding in ("utf-8", "latin-1", "unicode_escape"):
            try:
                return json.dumps(data, encoding=encoding)
            # Old systems using simplejson module does not support encoding keyword.
            except TypeError, e:
                return json.dumps(data)
            except UnicodeDecodeError, e:
                continue
        self.fail_json(msg='Invalid unicode encoding encountered')

    def from_json(self, data):
        return json.loads(data)

    def add_cleanup_file(self, path):
        if path not in self.cleanup_files:
            self.cleanup_files.append(path)

    def do_cleanup_files(self):
        for path in self.cleanup_files:
            self.cleanup(path)

    def exit_json(self, **kwargs):
        ''' return from the module, without error '''
        self.add_path_info(kwargs)
        #if not 'changed' in kwargs:
        #    kwargs['changed'] = False
	if 'changed' in kwargs:
	    del kwargs['changed']
        self.do_cleanup_files()
        print self.jsonify(kwargs)
        sys.exit(0)

    def fail_json(self, **kwargs):
        ''' return from the module, with an error message '''
        self.add_path_info(kwargs)
        assert 'msg' in kwargs, "implementation error -- msg to explain the error is required"
        kwargs['failed'] = True
        self.do_cleanup_files()
        print self.jsonify(kwargs)
        sys.exit(1)

    def is_executable(self, path):
        '''is the given path executable?'''
        return (stat.S_IXUSR & os.stat(path)[stat.ST_MODE]
                or stat.S_IXGRP & os.stat(path)[stat.ST_MODE]
                or stat.S_IXOTH & os.stat(path)[stat.ST_MODE])

    def digest_from_file(self, filename, digest_method):
        ''' Return hex digest of local file for a given digest_method, or None if file is not present. '''
        if not os.path.exists(filename):
            return None
        if os.path.isdir(filename):
            self.fail_json(msg="attempted to take checksum of directory: %s" % filename)
        digest = digest_method
        blocksize = 64 * 1024
        infile = open(filename, 'rb')
        block = infile.read(blocksize)
        while block:
            digest.update(block)
            block = infile.read(blocksize)
        infile.close()
        return digest.hexdigest()

    def md5(self, filename):
        ''' Return MD5 hex digest of local file using digest_from_file().

        Do not use this function unless you have no other choice for:
            1) Optional backwards compatibility
            2) Compatibility with a third party protocol

        This function will not work on systems complying with FIPS-140-2.

        Most uses of this function can use the module.sha1 function instead.
        '''
        if not _md5:
            raise ValueError('MD5 not available.  Possibly running in FIPS mode')
        return self.digest_from_file(filename, _md5())

    def sha1(self, filename):
        ''' Return SHA1 hex digest of local file using digest_from_file(). '''
        return self.digest_from_file(filename, _sha1())

    def sha256(self, filename):
        ''' Return SHA-256 hex digest of local file using digest_from_file(). '''
        if not HAVE_HASHLIB:
            self.fail_json(msg="SHA-256 checksums require hashlib, which is available in Python 2.5 and higher")
        return self.digest_from_file(filename, _sha256())

    def backup_local(self, fn):
        '''make a date-marked backup of the specified file, return True or False on success or failure'''
        # backups named basename-YYYY-MM-DD@HH:MM~
        ext = time.strftime("%Y-%m-%d@%H:%M~", time.localtime(time.time()))
        backupdest = '%s.%s' % (fn, ext)

        try:
            shutil.copy2(fn, backupdest)
        except shutil.Error, e:
            self.fail_json(msg='Could not make backup of %s to %s: %s' % (fn, backupdest, e))
        return backupdest

    def cleanup(self, tmpfile):
        if os.path.exists(tmpfile):
            try:
                os.unlink(tmpfile)
            except OSError, e:
                sys.stderr.write("could not cleanup %s: %s" % (tmpfile, e))

    def atomic_move(self, src, dest):
        '''atomically move src to dest, copying attributes from dest, returns true on success
        it uses os.rename to ensure this as it is an atomic operation, rest of the function is
        to work around limitations, corner cases and ensure selinux context is saved if possible'''
        context = None
        dest_stat = None
        if os.path.exists(dest):
            try:
                dest_stat = os.stat(dest)
                os.chmod(src, dest_stat.st_mode & 07777)
                os.chown(src, dest_stat.st_uid, dest_stat.st_gid)
            except OSError, e:
                if e.errno != errno.EPERM:
                    raise
            if self.selinux_enabled():
                context = self.selinux_context(dest)
        else:
            if self.selinux_enabled():
                context = self.selinux_default_context(dest)

        creating = not os.path.exists(dest)

        try:
            login_name = os.getlogin()
        except OSError:
            # not having a tty can cause the above to fail, so
            # just get the LOGNAME environment variable instead
            login_name = os.environ.get('LOGNAME', None)

        # if the original login_name doesn't match the currently
        # logged-in user, or if the SUDO_USER environment variable
        # is set, then this user has switched their credentials
        switched_user = login_name and login_name != pwd.getpwuid(os.getuid())[0] or os.environ.get('SUDO_USER')

        try:
            # Optimistically try a rename, solves some corner cases and can avoid useless work, throws exception if not atomic.
            os.rename(src, dest)
        except (IOError,OSError), e:
            # only try workarounds for errno 18 (cross device), 1 (not permitted) and 13 (permission denied)
            if e.errno != errno.EPERM and e.errno != errno.EXDEV and e.errno != errno.EACCES:
                self.fail_json(msg='Could not replace file: %s to %s: %s' % (src, dest, e))

            dest_dir = os.path.dirname(dest)
            dest_file = os.path.basename(dest)
            try:
                tmp_dest = tempfile.NamedTemporaryFile(
                    prefix=".ansible_tmp", dir=dest_dir, suffix=dest_file)
            except (OSError, IOError), e:
                self.fail_json(msg='The destination directory (%s) is not writable by the current user.' % dest_dir)

            try: # leaves tmp file behind when sudo and  not root
                if switched_user and os.getuid() != 0:
                    # cleanup will happen by 'rm' of tempdir
                    # copy2 will preserve some metadata
                    shutil.copy2(src, tmp_dest.name)
                else:
                    shutil.move(src, tmp_dest.name)
                if self.selinux_enabled():
                    self.set_context_if_different(
                        tmp_dest.name, context, False)
                try:
                    tmp_stat = os.stat(tmp_dest.name)
                    if dest_stat and (tmp_stat.st_uid != dest_stat.st_uid or tmp_stat.st_gid != dest_stat.st_gid):
                        os.chown(tmp_dest.name, dest_stat.st_uid, dest_stat.st_gid)
                except OSError, e:
                    if e.errno != errno.EPERM:
                        raise
                os.rename(tmp_dest.name, dest)
            except (shutil.Error, OSError, IOError), e:
                self.cleanup(tmp_dest.name)
                self.fail_json(msg='Could not replace file: %s to %s: %s' % (src, dest, e))

        if creating:
            # make sure the file has the correct permissions
            # based on the current value of umask
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(dest, 0666 ^ umask)
            if switched_user:
                os.chown(dest, os.getuid(), os.getgid())

        if self.selinux_enabled():
            # rename might not preserve context
            self.set_context_if_different(dest, context, False)

    def run_command(self, args, check_rc=False, close_fds=True, executable=None, data=None, binary_data=False, path_prefix=None, cwd=None, use_unsafe_shell=False, prompt_regex=None):
        '''
        Execute a command, returns rc, stdout, and stderr.
        args is the command to run
        If args is a list, the command will be run with shell=False.
        If args is a string and use_unsafe_shell=False it will split args to a list and run with shell=False
        If args is a string and use_unsafe_shell=True it run with shell=True.
        Other arguments:
        - check_rc (boolean)    Whether to call fail_json in case of
                                non zero RC.  Default is False.
        - close_fds (boolean)   See documentation for subprocess.Popen().
                                Default is True.
        - executable (string)   See documentation for subprocess.Popen().
                                Default is None.
        - prompt_regex (string) A regex string (not a compiled regex) which
                                can be used to detect prompts in the stdout
                                which would otherwise cause the execution
                                to hang (especially if no input data is
                                specified)
        '''

        shell = False
        if isinstance(args, list):
            if use_unsafe_shell:
                args = " ".join([pipes.quote(x) for x in args])
                shell = True
        elif isinstance(args, basestring) and use_unsafe_shell:
            shell = True
        elif isinstance(args, basestring):
            args = shlex.split(args.encode('utf-8'))
        else:
            msg = "Argument 'args' to run_command must be list or string"
            self.fail_json(rc=257, cmd=args, msg=msg)

        prompt_re = None
        if prompt_regex:
            try:
                prompt_re = re.compile(prompt_regex, re.MULTILINE)
            except re.error:
                self.fail_json(msg="invalid prompt regular expression given to run_command")

        # expand things like $HOME and ~
        if not shell:
            args = [ os.path.expandvars(os.path.expanduser(x)) for x in args ]

        rc = 0
        msg = None
        st_in = None

        # Set a temporart env path if a prefix is passed
        env=os.environ
        if path_prefix:
            env['PATH']="%s:%s" % (path_prefix, env['PATH'])

        # create a printable version of the command for use
        # in reporting later, which strips out things like
        # passwords from the args list
        if isinstance(args, list):
            clean_args = " ".join(pipes.quote(arg) for arg in args)
        else:
            clean_args = args

        # all clean strings should return two match groups, 
        # where the first is the CLI argument and the second 
        # is the password/key/phrase that will be hidden
        clean_re_strings = [
            # this removes things like --password, --pass, --pass-wd, etc.
            # optionally followed by an '=' or a space. The password can 
            # be quoted or not too, though it does not care about quotes
            # that are not balanced
            # source: http://blog.stevenlevithan.com/archives/match-quoted-string
            r'([-]{0,2}pass[-]?(?:word|wd)?[=\s]?)((?:["\'])?(?:[^\s])*(?:\1)?)',
            r'^(?P<before>.*:)(?P<password>.*)(?P<after>\@.*)$', 
            # TODO: add more regex checks here
        ]
        for re_str in clean_re_strings:
            r = re.compile(re_str)
            clean_args = r.sub(r'\1********', clean_args)

        if data:
            st_in = subprocess.PIPE

        kwargs = dict(
            executable=executable,
            shell=shell,
            close_fds=close_fds,
            stdin=st_in,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE 
        )

        if path_prefix:
            kwargs['env'] = env
        if cwd and os.path.isdir(cwd):
            kwargs['cwd'] = cwd

        # store the pwd
        prev_dir = os.getcwd()

        # make sure we're in the right working directory
        if cwd and os.path.isdir(cwd):
            try:
                os.chdir(cwd)
            except (OSError, IOError), e:
                self.fail_json(rc=e.errno, msg="Could not open %s, %s" % (cwd, str(e)))

        try:
            cmd = subprocess.Popen(args, **kwargs)

            # the communication logic here is essentially taken from that
            # of the _communicate() function in ssh.py

            stdout = ''
            stderr = ''
            rpipes = [cmd.stdout, cmd.stderr]

            if data:
                if not binary_data:
                    data += '\n'
                cmd.stdin.write(data)
                cmd.stdin.close()

            while True:
                rfd, wfd, efd = select.select(rpipes, [], rpipes, 1)
                if cmd.stdout in rfd:
                    dat = os.read(cmd.stdout.fileno(), 9000)
                    stdout += dat
                    if dat == '':
                        rpipes.remove(cmd.stdout)
                if cmd.stderr in rfd:
                    dat = os.read(cmd.stderr.fileno(), 9000)
                    stderr += dat
                    if dat == '':
                        rpipes.remove(cmd.stderr)
                # if we're checking for prompts, do it now
                if prompt_re:
                    if prompt_re.search(stdout) and not data:
                         return (257, stdout, "A prompt was encountered while running a command, but no input data was specified")
                # only break out if no pipes are left to read or
                # the pipes are completely read and
                # the process is terminated
                if (not rpipes or not rfd) and cmd.poll() is not None:
                    break
                # No pipes are left to read but process is not yet terminated
                # Only then it is safe to wait for the process to be finished
                # NOTE: Actually cmd.poll() is always None here if rpipes is empty
                elif not rpipes and cmd.poll() == None:
                    cmd.wait()
                    # The process is terminated. Since no pipes to read from are
                    # left, there is no need to call select() again.
                    break

            cmd.stdout.close()
            cmd.stderr.close()

            rc = cmd.returncode
        except (OSError, IOError), e:
            self.fail_json(rc=e.errno, msg=str(e), cmd=clean_args)
        except:
            self.fail_json(rc=257, msg=traceback.format_exc(), cmd=clean_args)

        if rc != 0 and check_rc:
            msg = stderr.rstrip()
            self.fail_json(cmd=clean_args, rc=rc, stdout=stdout, stderr=stderr, msg=msg)

        # reset the pwd
        os.chdir(prev_dir)

        return (rc, stdout, stderr)

    def append_to_file(self, filename, str):
        filename = os.path.expandvars(os.path.expanduser(filename))
        fh = open(filename, 'a')
        fh.write(str)
        fh.close()

    def pretty_bytes(self,size):
        ranges = (
                (1<<70L, 'ZB'),
                (1<<60L, 'EB'),
                (1<<50L, 'PB'),
                (1<<40L, 'TB'),
                (1<<30L, 'GB'),
                (1<<20L, 'MB'),
                (1<<10L, 'KB'),
                (1, 'Bytes')
            )
        for limit, suffix in ranges:
            if size >= limit:
                break
        return '%.2f %s' % (float(size)/ limit, suffix)

def get_module_path():
    return os.path.dirname(os.path.realpath(__file__))

# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import os
import stat
import array
import errno
import fcntl
import fnmatch
import glob
import platform
import re
import signal
import socket
import struct
import datetime
import getpass
import ConfigParser
import StringIO

from string import maketrans

try:
    import selinux
    HAVE_SELINUX=True
except ImportError:
    HAVE_SELINUX=False

try:
    import json
except ImportError:
    import simplejson as json

# --------------------------------------------------------------
# timeout function to make sure some fact gathering 
# steps do not exceed a time limit

class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message="Timer expired"):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator

# --------------------------------------------------------------

class Facts(object):
    """
    This class should only attempt to populate those facts that
    are mostly generic to all systems.  This includes platform facts,
    service facts (e.g. ssh keys or selinux), and distribution facts.
    Anything that requires extensive code or may have more than one
    possible implementation to establish facts for a given topic should
    subclass Facts.
    """

    _I386RE = re.compile(r'i[3456]86')
    # For the most part, we assume that platform.dist() will tell the truth.
    # This is the fallback to handle unknowns or exceptions
    OSDIST_LIST = ( ('/etc/redhat-release', 'RedHat'),
                    ('/etc/vmware-release', 'VMwareESX'),
                    ('/etc/openwrt_release', 'OpenWrt'),
                    ('/etc/system-release', 'OtherLinux'),
                    ('/etc/alpine-release', 'Alpine'),
                    ('/etc/release', 'Solaris'),
                    ('/etc/arch-release', 'Archlinux'),
                    ('/etc/SuSE-release', 'SuSE'),
                    ('/etc/os-release', 'SuSE'),
                    ('/etc/gentoo-release', 'Gentoo'),
                    ('/etc/os-release', 'Debian'),
                    ('/etc/lsb-release', 'Mandriva') )
    SELINUX_MODE_DICT = { 1: 'enforcing', 0: 'permissive', -1: 'disabled' }

    # A list of dicts.  If there is a platform with more than one
    # package manager, put the preferred one last.  If there is an
    # ansible module, use that as the value for the 'name' key.
    PKG_MGRS = [ { 'path' : '/usr/bin/yum',         'name' : 'yum' },
                 { 'path' : '/usr/bin/apt-get',     'name' : 'apt' },
                 { 'path' : '/usr/bin/zypper',      'name' : 'zypper' },
                 { 'path' : '/usr/sbin/urpmi',      'name' : 'urpmi' },
                 { 'path' : '/usr/bin/pacman',      'name' : 'pacman' },
                 { 'path' : '/bin/opkg',            'name' : 'opkg' },
                 { 'path' : '/opt/local/bin/pkgin', 'name' : 'pkgin' },
                 { 'path' : '/opt/local/bin/port',  'name' : 'macports' },
                 { 'path' : '/sbin/apk',            'name' : 'apk' },
                 { 'path' : '/usr/sbin/pkg',        'name' : 'pkgng' },
                 { 'path' : '/usr/sbin/swlist',     'name' : 'SD-UX' },
                 { 'path' : '/usr/bin/emerge',      'name' : 'portage' },
                 { 'path' : '/usr/sbin/pkgadd',     'name' : 'svr4pkg' },
                 { 'path' : '/usr/bin/pkg',         'name' : 'pkg' },
    ]

    def __init__(self):
        self.facts = {}
        self.get_platform_facts()
        #self.get_distribution_facts()
        #self.get_cmdline()
        #self.get_public_ssh_host_keys()
        #self.get_selinux_facts()
        #self.get_fips_facts()
        #self.get_pkg_mgr_facts()
        #self.get_lsb_facts()
        #self.get_date_time_facts()
        #self.get_user_facts()
        #self.get_local_facts()
        #self.get_env_facts()

    def populate(self):
        return self.facts

    # Platform
    # platform.system() can be Linux, Darwin, Java, or Windows
    def get_platform_facts(self):
        self.facts['system'] = platform.system()
        self.facts['kernel'] = platform.release()
        self.facts['machine'] = platform.machine()
        #self.facts['python_version'] = platform.python_version()
        #self.facts['fqdn'] = socket.getfqdn()
        self.facts['hostname'] = platform.node().split('.')[0]
        #self.facts['nodename'] = platform.node()
        #self.facts['domain'] = '.'.join(self.facts['fqdn'].split('.')[1:])
        arch_bits = platform.architecture()[0]
        self.facts['userspace_bits'] = arch_bits.replace('bit', '')
        if self.facts['machine'] == 'x86_64':
            self.facts['architecture'] = self.facts['machine']
            if self.facts['userspace_bits'] == '64':
                self.facts['userspace_architecture'] = 'x86_64'
            elif self.facts['userspace_bits'] == '32':
                self.facts['userspace_architecture'] = 'i386'
        elif Facts._I386RE.search(self.facts['machine']):
            self.facts['architecture'] = 'i386'
            if self.facts['userspace_bits'] == '64':
                self.facts['userspace_architecture'] = 'x86_64'
            elif self.facts['userspace_bits'] == '32':
                self.facts['userspace_architecture'] = 'i386'
        else:
            self.facts['architecture'] = self.facts['machine']
        if self.facts['system'] == 'Linux':
            self.get_distribution_facts()
        elif self.facts['system'] == 'AIX':
            rc, out, err = module.run_command("/usr/sbin/bootinfo -p")
            data = out.split('\n')
            self.facts['architecture'] = data[0]


    def get_local_facts(self):

        fact_path = module.params.get('fact_path', None)
        if not fact_path or not os.path.exists(fact_path):
            return

        local = {}
        for fn in sorted(glob.glob(fact_path + '/*.fact')):
            # where it will sit under local facts
            fact_base = os.path.basename(fn).replace('.fact','')
            if stat.S_IXUSR & os.stat(fn)[stat.ST_MODE]:
                # run it
                # try to read it as json first
                # if that fails read it with ConfigParser
                # if that fails, skip it
                rc, out, err = module.run_command(fn)
            else:
                out = open(fn).read()

            # load raw json
            fact = 'loading %s' % fact_base
            try:
                fact = json.loads(out)
            except ValueError, e:
                # load raw ini
                cp = ConfigParser.ConfigParser()
                try:
                    cp.readfp(StringIO.StringIO(out))
                except ConfigParser.Error, e:
                    fact="error loading fact - please check content"
                else:
                    fact = {}
                    #print cp.sections()
                    for sect in cp.sections():
                        if sect not in fact:
                            fact[sect] = {}
                        for opt in cp.options(sect):
                            val = cp.get(sect, opt)
                            fact[sect][opt]=val

            local[fact_base] = fact
        if not local:
            return
        self.facts['local'] = local

    # platform.dist() is deprecated in 2.6
    # in 2.6 and newer, you should use platform.linux_distribution()
    def get_distribution_facts(self):

        # A list with OS Family members
        OS_FAMILY = dict(
            RedHat = 'RedHat', Fedora = 'RedHat', CentOS = 'RedHat', Scientific = 'RedHat',
            SLC = 'RedHat', Ascendos = 'RedHat', CloudLinux = 'RedHat', PSBM = 'RedHat',
            OracleLinux = 'RedHat', OVS = 'RedHat', OEL = 'RedHat', Amazon = 'RedHat',
            XenServer = 'RedHat', Ubuntu = 'Debian', Debian = 'Debian', SLES = 'Suse',
            SLED = 'Suse', OpenSuSE = 'Suse', SuSE = 'Suse', Gentoo = 'Gentoo', Funtoo = 'Gentoo',
            Archlinux = 'Archlinux', Mandriva = 'Mandrake', Mandrake = 'Mandrake',
            Solaris = 'Solaris', Nexenta = 'Solaris', OmniOS = 'Solaris', OpenIndiana = 'Solaris',
            SmartOS = 'Solaris', AIX = 'AIX', Alpine = 'Alpine', MacOSX = 'Darwin',
            FreeBSD = 'FreeBSD', HPUX = 'HP-UX'
        )

        # TODO: Rewrite this to use the function references in a dict pattern
        # as it's much cleaner than this massive if-else
        if self.facts['system'] == 'AIX':
            self.facts['distribution'] = 'AIX'
            rc, out, err = module.run_command("/usr/bin/oslevel")
            data = out.split('.')
            self.facts['distribution_version'] = data[0]
            self.facts['distribution_release'] = data[1]
        elif self.facts['system'] == 'HP-UX':
            self.facts['distribution'] = 'HP-UX'
            rc, out, err = module.run_command("/usr/sbin/swlist |egrep 'HPUX.*OE.*[AB].[0-9]+\.[0-9]+'", use_unsafe_shell=True)
            data = re.search('HPUX.*OE.*([AB].[0-9]+\.[0-9]+)\.([0-9]+).*', out)
            if data:
                self.facts['distribution_version'] = data.groups()[0]
                self.facts['distribution_release'] = data.groups()[1]
        elif self.facts['system'] == 'Darwin':
            self.facts['distribution'] = 'MacOSX'
            rc, out, err = module.run_command("/usr/bin/sw_vers -productVersion")
            data = out.split()[-1]
            self.facts['distribution_version'] = data
        elif self.facts['system'] == 'FreeBSD':
            self.facts['distribution'] = 'FreeBSD'
            self.facts['distribution_release'] = platform.release()
            self.facts['distribution_version'] = platform.version()
        elif self.facts['system'] == 'OpenBSD':
            self.facts['distribution'] = 'OpenBSD'
            self.facts['distribution_release'] = platform.release()
            rc, out, err = module.run_command("/sbin/sysctl -n kern.version")
            match = re.match('OpenBSD\s[0-9]+.[0-9]+-(\S+)\s.*', out)
            if match:
                self.facts['distribution_version'] = match.groups()[0]
            else:
                self.facts['distribution_version'] = 'release'
        else:
            dist = platform.dist()
            self.facts['distribution'] = dist[0].capitalize() or 'NA'
            self.facts['distribution_version'] = dist[1] or 'NA'
            self.facts['distribution_major_version'] = dist[1].split('.')[0] or 'NA'
            self.facts['distribution_release'] = dist[2] or 'NA'
            # Try to handle the exceptions now ...
            for (path, name) in Facts.OSDIST_LIST:
                if os.path.exists(path) and os.path.getsize(path) > 0:
                    if self.facts['distribution'] in ('Fedora', ):
                        # Once we determine the value is one of these distros
                        # we trust the values are always correct
                        break
                    elif name == 'RedHat':
                        data = get_file_content(path)
                        if 'Red Hat' in data:
                            self.facts['distribution'] = name
                        else:
                            self.facts['distribution'] = data.split()[0]
                        break
                    elif name == 'OtherLinux':
                        data = get_file_content(path)
                        if 'Amazon' in data:
                            self.facts['distribution'] = 'Amazon'
                            self.facts['distribution_version'] = data.split()[-1]
                            break
                    elif name == 'OpenWrt':
                        data = get_file_content(path)
                        if 'OpenWrt' in data:
                            self.facts['distribution'] = name
                            version = re.search('DISTRIB_RELEASE="(.*)"', data)
                            if version:
                                self.facts['distribution_version'] = version.groups()[0]
                            release = re.search('DISTRIB_CODENAME="(.*)"', data)
                            if release:
                                self.facts['distribution_release'] = release.groups()[0]
                            break
                    elif name == 'Alpine':
                        data = get_file_content(path)
                        self.facts['distribution'] = name
                        self.facts['distribution_version'] = data
                        break
                    elif name == 'Solaris':
                        data = get_file_content(path).split('\n')[0]
                        if 'Solaris' in data:
                            ora_prefix = ''
                            if 'Oracle Solaris' in data:
                                data = data.replace('Oracle ','')
                                ora_prefix = 'Oracle '
                            self.facts['distribution'] = data.split()[0]
                            self.facts['distribution_version'] = data.split()[1]
                            self.facts['distribution_release'] = ora_prefix + data
                            break
                    elif name == 'SuSE':
                        data = get_file_content(path)
                        if 'suse' in data.lower():
                            if path == '/etc/os-release':
                                release = re.search("PRETTY_NAME=[^(]+ \(?([^)]+?)\)", data)
                                if release:
                                    self.facts['distribution_release'] = release.groups()[0]
                                    break
                            elif path == '/etc/SuSE-release':
                                data = data.splitlines()
                                for line in data:
                                    release = re.search('CODENAME *= *([^\n]+)', line)
                                    if release:
                                        self.facts['distribution_release'] = release.groups()[0].strip()
                                        break
                    elif name == 'Debian':
                        data = get_file_content(path)
                        if 'Debian' in data:
                            release = re.search("PRETTY_NAME=[^(]+ \(?([^)]+?)\)", data)
                            if release:
                                self.facts['distribution_release'] = release.groups()[0]
                            break
                    elif name == 'Mandriva':
                        data = get_file_content(path)
                        if 'Mandriva' in data:
                            version = re.search('DISTRIB_RELEASE="(.*)"', data)
                            if version:
                                self.facts['distribution_version'] = version.groups()[0]
                            release = re.search('DISTRIB_CODENAME="(.*)"', data)
                            if release:
                                self.facts['distribution_release'] = release.groups()[0]
                            self.facts['distribution'] = name
                            break
                    else:
                        self.facts['distribution'] = name

        self.facts['os_family'] = self.facts['distribution']
        if self.facts['distribution'] in OS_FAMILY:
            self.facts['os_family'] = OS_FAMILY[self.facts['distribution']]

    def get_cmdline(self):
        data = get_file_content('/proc/cmdline')
        if data:
            self.facts['cmdline'] = {}
            try:
                for piece in shlex.split(data):
                    item = piece.split('=', 1)
                    if len(item) == 1:
                        self.facts['cmdline'][item[0]] = True
                    else:
                        self.facts['cmdline'][item[0]] = item[1]
            except ValueError, e:
                pass

    def get_public_ssh_host_keys(self):
        dsa_filename = '/etc/ssh/ssh_host_dsa_key.pub'
        rsa_filename = '/etc/ssh/ssh_host_rsa_key.pub'
        ecdsa_filename = '/etc/ssh/ssh_host_ecdsa_key.pub'

        if self.facts['system'] == 'Darwin':
            dsa_filename = '/etc/ssh_host_dsa_key.pub'
            rsa_filename = '/etc/ssh_host_rsa_key.pub'
            ecdsa_filename = '/etc/ssh_host_ecdsa_key.pub'
        dsa = get_file_content(dsa_filename)
        rsa = get_file_content(rsa_filename)
        ecdsa = get_file_content(ecdsa_filename)
        if dsa is None:
            dsa = 'NA'
        else:
            self.facts['ssh_host_key_dsa_public'] = dsa.split()[1]
        if rsa is None:
            rsa = 'NA'
        else:
            self.facts['ssh_host_key_rsa_public'] = rsa.split()[1]
        if ecdsa is None:
            ecdsa = 'NA'
        else:
            self.facts['ssh_host_key_ecdsa_public'] = ecdsa.split()[1]

    def get_pkg_mgr_facts(self):
        self.facts['pkg_mgr'] = 'unknown'
        for pkg in Facts.PKG_MGRS:
            if os.path.exists(pkg['path']):
                self.facts['pkg_mgr'] = pkg['name']
        if self.facts['system'] == 'OpenBSD':
                self.facts['pkg_mgr'] = 'openbsd_pkg'

    def get_lsb_facts(self):
        lsb_path = module.get_bin_path('lsb_release')
        if lsb_path:
            rc, out, err = module.run_command([lsb_path, "-a"])
            if rc == 0:
                self.facts['lsb'] = {}
            for line in out.split('\n'):
                if len(line) < 1:
                    continue
                value = line.split(':', 1)[1].strip()
                if 'LSB Version:' in line:
                    self.facts['lsb']['release'] = value
                elif 'Distributor ID:' in line:
                    self.facts['lsb']['id'] = value
                elif 'Description:' in line:
                    self.facts['lsb']['description'] = value
                elif 'Release:' in line:
                    self.facts['lsb']['release'] = value
                elif 'Codename:' in line:
                    self.facts['lsb']['codename'] = value
            if 'lsb' in self.facts and 'release' in self.facts['lsb']:
                self.facts['lsb']['major_release'] = self.facts['lsb']['release'].split('.')[0]
        elif lsb_path is None and os.path.exists('/etc/lsb-release'):
            self.facts['lsb'] = {}
            f = open('/etc/lsb-release', 'r')
            try:
                for line in f.readlines():
                    value = line.split('=',1)[1].strip()
                    if 'DISTRIB_ID' in line:
                        self.facts['lsb']['id'] = value
                    elif 'DISTRIB_RELEASE' in line:
                        self.facts['lsb']['release'] = value
                    elif 'DISTRIB_DESCRIPTION' in line:
                        self.facts['lsb']['description'] = value
                    elif 'DISTRIB_CODENAME' in line:
                        self.facts['lsb']['codename'] = value
            finally:
                f.close()
        else:
            return self.facts

        if 'lsb' in self.facts and 'release' in self.facts['lsb']:
            self.facts['lsb']['major_release'] = self.facts['lsb']['release'].split('.')[0]


    def get_selinux_facts(self):
        if not HAVE_SELINUX:
            self.facts['selinux'] = False
            return
        self.facts['selinux'] = {}
        if not selinux.is_selinux_enabled():
            self.facts['selinux']['status'] = 'disabled'
        else:
            self.facts['selinux']['status'] = 'enabled'
            try:
                self.facts['selinux']['policyvers'] = selinux.security_policyvers()
            except OSError, e:
                self.facts['selinux']['policyvers'] = 'unknown'
            try:
                (rc, configmode) = selinux.selinux_getenforcemode()
                if rc == 0:
                    self.facts['selinux']['config_mode'] = Facts.SELINUX_MODE_DICT.get(configmode, 'unknown')
                else:
                    self.facts['selinux']['config_mode'] = 'unknown'
            except OSError, e:
                self.facts['selinux']['config_mode'] = 'unknown'
            try:
                mode = selinux.security_getenforce()
                self.facts['selinux']['mode'] = Facts.SELINUX_MODE_DICT.get(mode, 'unknown')
            except OSError, e:
                self.facts['selinux']['mode'] = 'unknown'
            try:
                (rc, policytype) = selinux.selinux_getpolicytype()
                if rc == 0:
                    self.facts['selinux']['type'] = policytype
                else:
                    self.facts['selinux']['type'] = 'unknown'
            except OSError, e:
                self.facts['selinux']['type'] = 'unknown'


    def get_fips_facts(self):
        self.facts['fips'] = False
        data = get_file_content('/proc/sys/crypto/fips_enabled')
        if data and data == '1':
            self.facts['fips'] = True


    def get_date_time_facts(self):
        self.facts['date_time'] = {}

        now = datetime.datetime.now()
        self.facts['date_time']['year'] = now.strftime('%Y')
        self.facts['date_time']['month'] = now.strftime('%m')
        self.facts['date_time']['weekday'] = now.strftime('%A')
        self.facts['date_time']['day'] = now.strftime('%d')
        self.facts['date_time']['hour'] = now.strftime('%H')
        self.facts['date_time']['minute'] = now.strftime('%M')
        self.facts['date_time']['second'] = now.strftime('%S')
        self.facts['date_time']['epoch'] = now.strftime('%s')
        if self.facts['date_time']['epoch'] == '' or self.facts['date_time']['epoch'][0] == '%':
            self.facts['date_time']['epoch'] = str(int(time.time()))
        self.facts['date_time']['date'] = now.strftime('%Y-%m-%d')
        self.facts['date_time']['time'] = now.strftime('%H:%M:%S')
        self.facts['date_time']['iso8601_micro'] = now.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.facts['date_time']['iso8601'] = now.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        self.facts['date_time']['tz'] = time.strftime("%Z")
        self.facts['date_time']['tz_offset'] = time.strftime("%z")


    # User
    def get_user_facts(self):
        self.facts['user_id'] = getpass.getuser()

    def get_env_facts(self):
        self.facts['env'] = {}
        for k,v in os.environ.iteritems():
            self.facts['env'][k] = v

class Hardware(Facts):
    """
    This is a generic Hardware subclass of Facts.  This should be further
    subclassed to implement per platform.  If you subclass this, it
    should define:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count

    All subclasses MUST define platform.
    """
    platform = 'Generic'

    def __new__(cls, *arguments, **keyword):
        subclass = cls
        for sc in Hardware.__subclasses__():
            if sc.platform == platform.system():
                subclass = sc
        return super(cls, subclass).__new__(subclass, *arguments, **keyword)

    def __init__(self):
        Facts.__init__(self)

    def populate(self):
        return self.facts

class LinuxHardware(Hardware):
    """
    Linux-specific subclass of Hardware.  Defines memory and CPU facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count

    In addition, it also defines number of DMI facts and device facts.
    """

    platform = 'Linux'
    # MEMORY_FACTS = ['MemTotal', 'SwapTotal', 'MemFree', 'SwapFree']
    MEMORY_FACTS = ['MemTotal', 'SwapTotal']

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        self.get_dmi_facts()
        self.get_device_facts()
        #try:
        #    self.get_mount_facts()
        #except TimeoutError:
        #    pass
        return self.facts

    def get_memory_facts(self):
        if not os.access("/proc/meminfo", os.R_OK):
            return
        for line in open("/proc/meminfo").readlines():
            data = line.split(":", 1)
            key = data[0]
            if key in LinuxHardware.MEMORY_FACTS:
                val = data[1].strip().split(' ')[0]
                self.facts["%s_mb" % key.lower()] = long(val) / 1024

    def get_cpu_facts(self):
        i = 0
        physid = 0
        coreid = 0
        sockets = {}
        cores = {}
        if not os.access("/proc/cpuinfo", os.R_OK):
            return
        self.facts['processor'] = []
        for line in open("/proc/cpuinfo").readlines():
            data = line.split(":", 1)
            key = data[0].strip()
            # model name is for Intel arch, Processor (mind the uppercase P)
            # works for some ARM devices, like the Sheevaplug.
            if key == 'model name' or key == 'Processor' or key == 'vendor_id':
                if 'processor' not in self.facts:
                    self.facts['processor'] = []
                self.facts['processor'].append(data[1].strip())
                i += 1
            elif key == 'physical id':
                physid = data[1].strip()
                if physid not in sockets:
                    sockets[physid] = 1
            elif key == 'core id':
                coreid = data[1].strip()
                if coreid not in sockets:
                    cores[coreid] = 1
            elif key == 'cpu cores':
                sockets[physid] = int(data[1].strip())
            elif key == 'siblings':
                cores[coreid] = int(data[1].strip())
            elif key == '# processors':
                self.facts['processor_cores'] = int(data[1].strip())
        if self.facts['architecture'] != 's390x':
            self.facts['processor_count'] = sockets and len(sockets) or i
            self.facts['processor_cores'] = sockets.values() and sockets.values()[0] or 1
            self.facts['processor_threads_per_core'] = ((cores.values() and
                cores.values()[0] or 1) / self.facts['processor_cores'])
            self.facts['processor_vcpus'] = (self.facts['processor_threads_per_core'] *
                self.facts['processor_count'] * self.facts['processor_cores'])

    def get_dmi_facts(self):
        ''' learn dmi facts from system

        Try /sys first for dmi related facts.
        If that is not available, fall back to dmidecode executable '''

        if os.path.exists('/sys/devices/virtual/dmi/id/product_name'):
            # Use kernel DMI info, if available

            # DMI SPEC -- http://www.dmtf.org/sites/default/files/standards/documents/DSP0134_2.7.0.pdf
            FORM_FACTOR = [ "Unknown", "Other", "Unknown", "Desktop",
                            "Low Profile Desktop", "Pizza Box", "Mini Tower", "Tower",
                            "Portable", "Laptop", "Notebook", "Hand Held", "Docking Station",
                            "All In One", "Sub Notebook", "Space-saving", "Lunch Box",
                            "Main Server Chassis", "Expansion Chassis", "Sub Chassis",
                            "Bus Expansion Chassis", "Peripheral Chassis", "RAID Chassis",
                            "Rack Mount Chassis", "Sealed-case PC", "Multi-system",
                            "CompactPCI", "AdvancedTCA", "Blade" ]

            DMI_DICT = {
                    'bios_date': '/sys/devices/virtual/dmi/id/bios_date',
                    #'bios_version': '/sys/devices/virtual/dmi/id/bios_version',
                    #'form_factor': '/sys/devices/virtual/dmi/id/chassis_type',
                    'product_name': '/sys/devices/virtual/dmi/id/product_name',
                    'product_serial': '/sys/devices/virtual/dmi/id/product_serial',
                    #'product_uuid': '/sys/devices/virtual/dmi/id/product_uuid',
                    #'product_version': '/sys/devices/virtual/dmi/id/product_version',
                    'system_vendor': '/sys/devices/virtual/dmi/id/sys_vendor'
                    }

            for (key,path) in DMI_DICT.items():
                data = get_file_content(path)
                if data is not None:
                    if key == 'form_factor':
                        try:
                            self.facts['form_factor'] = FORM_FACTOR[int(data)]
                        except IndexError, e:
                            self.facts['form_factor'] = 'unknown (%s)' % data
                    else:
                        self.facts[key] = data
                else:
                    self.facts[key] = 'NA'

        else:
            # Fall back to using dmidecode, if available
            dmi_bin = module.get_bin_path('dmidecode')
            DMI_DICT = {
                    'bios_date': 'bios-release-date',
                    #'bios_version': 'bios-version',
                    #'form_factor': 'chassis-type',
                    'product_name': 'system-product-name',
                    'product_serial': 'system-serial-number',
                    #'product_uuid': 'system-uuid',
                    #'product_version': 'system-version',
                    'system_vendor': 'system-manufacturer'
                    }
            for (k, v) in DMI_DICT.items():
                if dmi_bin is not None:
                    (rc, out, err) = module.run_command('%s -s %s' % (dmi_bin, v))
                    if rc == 0:
                        # Strip out commented lines (specific dmidecode output)
                        thisvalue = ''.join([ line for line in out.split('\n') if not line.startswith('#') ])
                        try:
                            json.dumps(thisvalue)
                        except UnicodeDecodeError:
                            thisvalue = "NA"

                        self.facts[k] = thisvalue
                    else:
                        self.facts[k] = 'NA'
                else:
                    self.facts[k] = 'NA'

    @timeout(10)
    def get_mount_facts(self):
        self.facts['mounts'] = []
        mtab = get_file_content('/etc/mtab', '')
        for line in mtab.split('\n'):
            if line.startswith('/'):
                fields = line.rstrip('\n').split()
                if(fields[2] != 'none'):
                    size_total = None
                    size_available = None
                    try:
                        statvfs_result = os.statvfs(fields[1])
                        size_total = statvfs_result.f_bsize * statvfs_result.f_blocks
                        size_available = statvfs_result.f_bsize * (statvfs_result.f_bavail)
                    except OSError, e:
                        continue

                    self.facts['mounts'].append(
                        {'mount': fields[1],
                         'device':fields[0],
                         'fstype': fields[2],
                         'options': fields[3],
                         # statvfs data
                         'size_total': size_total,
                         'size_available': size_available,
                         })

    def get_device_facts(self):
        self.facts['devices'] = {}
        lspci = module.get_bin_path('lspci')
        if lspci:
            rc, pcidata, err = module.run_command([lspci, '-D'])
        else:
            pcidata = None

        try:
            block_devs = os.listdir("/sys/block")
        except OSError:
            return

        for block in block_devs:
            virtual = 1
            sysfs_no_links = 0
            try:
                path = os.readlink(os.path.join("/sys/block/", block))
            except OSError, e:
                if e.errno == errno.EINVAL:
                    path = block
                    sysfs_no_links = 1
                else:
                    continue
            if "virtual" in path:
                continue
            sysdir = os.path.join("/sys/block", path)
            if sysfs_no_links == 1:
                for folder in os.listdir(sysdir):
                    if "device" in folder:
                        virtual = 0
                        break
                if virtual:
                    continue
            d = {}
            diskname = os.path.basename(sysdir)
            for key in ['vendor', 'model']:
                d[key] = get_file_content(sysdir + "/device/" + key)

            for key,test in [ ('removable','/removable'), \
                              ('support_discard','/queue/discard_granularity'),
                              ]:
                d[key] = get_file_content(sysdir + test)

            d['partitions'] = {}
            for folder in os.listdir(sysdir):
                m = re.search("(" + diskname + "\d+)", folder)
                if m:
                    part = {}
                    partname = m.group(1)
                    part_sysdir = sysdir + "/" + partname

                    part['start'] = get_file_content(part_sysdir + "/start",0)
                    part['sectors'] = get_file_content(part_sysdir + "/size",0)
                    part['sectorsize'] = get_file_content(part_sysdir + "/queue/physical_block_size")
                    if not part['sectorsize']:
                        part['sectorsize'] = get_file_content(part_sysdir + "/queue/hw_sector_size",512)
                    part['size'] = module.pretty_bytes((float(part['sectors']) * float(part['sectorsize'])))
                    d['partitions'][partname] = part

            d['rotational'] = get_file_content(sysdir + "/queue/rotational")
            d['scheduler_mode'] = ""
            scheduler = get_file_content(sysdir + "/queue/scheduler")
            if scheduler is not None:
                m = re.match(".*?(\[(.*)\])", scheduler)
                if m:
                    d['scheduler_mode'] = m.group(2)

            d['sectors'] = get_file_content(sysdir + "/size")
            if not d['sectors']:
                d['sectors'] = 0
            d['sectorsize'] = get_file_content(sysdir + "/queue/physical_block_size")
            if not d['sectorsize']:
                d['sectorsize'] = get_file_content(sysdir + "/queue/hw_sector_size",512)
            d['size'] = module.pretty_bytes(float(d['sectors']) * float(d['sectorsize']))

            d['host'] = ""

            # domains are numbered (0 to ffff), bus (0 to ff), slot (0 to 1f), and function (0 to 7).
            m = re.match(".+/([a-f0-9]{4}:[a-f0-9]{2}:[0|1][a-f0-9]\.[0-7])/", sysdir)
            if m and pcidata:
                pciid = m.group(1)
                did = re.escape(pciid)
                m = re.search("^" + did + "\s(.*)$", pcidata, re.MULTILINE)
                d['host'] = m.group(1)

            d['holders'] = []
            if os.path.isdir(sysdir + "/holders"):
                for folder in os.listdir(sysdir + "/holders"):
                    if not folder.startswith("dm-"):
                        continue
                    name = get_file_content(sysdir + "/holders/" + folder + "/dm/name")
                    if name:
                        d['holders'].append(name)
                    else:
                        d['holders'].append(folder)

            self.facts['devices'][diskname] = d


class SunOSHardware(Hardware):
    """
    In addition to the generic memory and cpu facts, this also sets
    swap_reserved_mb and swap_allocated_mb that is available from *swap -s*.
    """
    platform = 'SunOS'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        return self.facts

    def get_cpu_facts(self):
        physid = 0
        sockets = {}
        rc, out, err = module.run_command("/usr/bin/kstat cpu_info")
        self.facts['processor'] = []
        for line in out.split('\n'):
            if len(line) < 1:
                continue
            data = line.split(None, 1)
            key = data[0].strip()
            # "brand" works on Solaris 10 & 11. "implementation" for Solaris 9.
            if key == 'module:':
                brand = ''
            elif key == 'brand':
                brand = data[1].strip()
            elif key == 'clock_MHz':
                clock_mhz = data[1].strip()
            elif key == 'implementation':
                processor = brand or data[1].strip()
                # Add clock speed to description for SPARC CPU
                if self.facts['machine'] != 'i86pc':
                    processor += " @ " + clock_mhz + "MHz"
                if 'processor' not in self.facts:
                    self.facts['processor'] = []
                self.facts['processor'].append(processor)
            elif key == 'chip_id':
                physid = data[1].strip()
                if physid not in sockets:
                    sockets[physid] = 1
                else:
                    sockets[physid] += 1
        # Counting cores on Solaris can be complicated.
        # https://blogs.oracle.com/mandalika/entry/solaris_show_me_the_cpu
        # Treat 'processor_count' as physical sockets and 'processor_cores' as
        # virtual CPUs visisble to Solaris. Not a true count of cores for modern SPARC as
        # these processors have: sockets -> cores -> threads/virtual CPU.
        if len(sockets) > 0:
            self.facts['processor_count'] = len(sockets)
            self.facts['processor_cores'] = reduce(lambda x, y: x + y, sockets.values())
        else:
            self.facts['processor_cores'] = 'NA'
            self.facts['processor_count'] = len(self.facts['processor'])

    def get_memory_facts(self):
        rc, out, err = module.run_command(["/usr/sbin/prtconf"])
        for line in out.split('\n'):
            if 'Memory size' in line:
                self.facts['memtotal_mb'] = line.split()[2]
        rc, out, err = module.run_command("/usr/sbin/swap -s")
        allocated = long(out.split()[1][:-1])
        reserved = long(out.split()[5][:-1])
        used = long(out.split()[8][:-1])
        free = long(out.split()[10][:-1])
        self.facts['swapfree_mb'] = free / 1024
        self.facts['swaptotal_mb'] = (free + used) / 1024
        self.facts['swap_allocated_mb'] = allocated / 1024
        self.facts['swap_reserved_mb'] = reserved / 1024

class OpenBSDHardware(Hardware):
    """
    OpenBSD-specific subclass of Hardware. Defines memory, CPU and device facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count
    - processor_speed
    - devices
    """
    platform = 'OpenBSD'
    DMESG_BOOT = '/var/run/dmesg.boot'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.sysctl = self.get_sysctl()
        self.get_memory_facts()
        self.get_processor_facts()
        self.get_device_facts()
        return self.facts

    def get_sysctl(self):
        rc, out, err = module.run_command(["/sbin/sysctl", "hw"])
        if rc != 0:
            return dict()
        sysctl = dict()
        for line in out.splitlines():
            (key, value) = line.split('=')
            sysctl[key] = value.strip()
        return sysctl

    def get_memory_facts(self):
        # Get free memory. vmstat output looks like:
        #  procs    memory       page                    disks    traps          cpu
        #  r b w    avm     fre  flt  re  pi  po  fr  sr wd0 fd0  int   sys   cs us sy id
        #  0 0 0  47512   28160   51   0   0   0   0   0   1   0  116    89   17  0  1 99
        rc, out, err = module.run_command("/usr/bin/vmstat")
        if rc == 0:
            self.facts['memfree_mb'] = long(out.splitlines()[-1].split()[4]) / 1024
            self.facts['memtotal_mb'] = long(self.sysctl['hw.usermem']) / 1024 / 1024

        # Get swapctl info. swapctl output looks like:
        # total: 69268 1K-blocks allocated, 0 used, 69268 available
        # And for older OpenBSD:
        # total: 69268k bytes allocated = 0k used, 69268k available
        rc, out, err = module.run_command("/sbin/swapctl -sk")
        if rc == 0:
            swaptrans = maketrans(' ', ' ')
            data = out.split()
            self.facts['swapfree_mb'] = long(data[-2].translate(swaptrans, "kmg")) / 1024
            self.facts['swaptotal_mb'] = long(data[1].translate(swaptrans, "kmg")) / 1024

    def get_processor_facts(self):
        processor = []
        dmesg_boot = get_file_content(OpenBSDHardware.DMESG_BOOT)
        if not dmesg_boot:
            rc, dmesg_boot, err = module.run_command("/sbin/dmesg")
        i = 0
        for line in dmesg_boot.splitlines():
            if line.split(' ', 1)[0] == 'cpu%i:' % i:
                processor.append(line.split(' ', 1)[1])
                i = i + 1
        processor_count = i
        self.facts['processor'] = processor
        self.facts['processor_count'] = processor_count
        # I found no way to figure out the number of Cores per CPU in OpenBSD
        self.facts['processor_cores'] = 'NA'

    def get_device_facts(self):
        devices = []
        devices.extend(self.sysctl['hw.disknames'].split(','))
        self.facts['devices'] = devices

class FreeBSDHardware(Hardware):
    """
    FreeBSD-specific subclass of Hardware.  Defines memory and CPU facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count
    - devices
    """
    platform = 'FreeBSD'
    DMESG_BOOT = '/var/run/dmesg.boot'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        self.get_dmi_facts()
        self.get_device_facts()
        try:
            self.get_mount_facts()
        except TimeoutError:
            pass
        return self.facts

    def get_cpu_facts(self):
        self.facts['processor'] = []
        rc, out, err = module.run_command("/sbin/sysctl -n hw.ncpu")
        self.facts['processor_count'] = out.strip()

        dmesg_boot = get_file_content(FreeBSDHardware.DMESG_BOOT)
        if not dmesg_boot:
            rc, dmesg_boot, err = module.run_command("/sbin/dmesg")
        for line in dmesg_boot.split('\n'):
            if 'CPU:' in line:
                cpu = re.sub(r'CPU:\s+', r"", line)
                self.facts['processor'].append(cpu.strip())
            if 'Logical CPUs per core' in line:
                self.facts['processor_cores'] = line.split()[4]


    def get_memory_facts(self):
        rc, out, err = module.run_command("/sbin/sysctl vm.stats")
        for line in out.split('\n'):
            data = line.split()
            if 'vm.stats.vm.v_page_size' in line:
                pagesize = long(data[1])
            if 'vm.stats.vm.v_page_count' in line:
                pagecount = long(data[1])
            if 'vm.stats.vm.v_free_count' in line:
                freecount = long(data[1])
        self.facts['memtotal_mb'] = pagesize * pagecount / 1024 / 1024
        self.facts['memfree_mb'] = pagesize * freecount / 1024 / 1024
        # Get swapinfo.  swapinfo output looks like:
        # Device          1M-blocks     Used    Avail Capacity
        # /dev/ada0p3        314368        0   314368     0%
        #
        rc, out, err = module.run_command("/usr/sbin/swapinfo -m")
        lines = out.split('\n')
        if len(lines[-1]) == 0:
            lines.pop()
        data = lines[-1].split()
        self.facts['swaptotal_mb'] = data[1]
        self.facts['swapfree_mb'] = data[3]

    @timeout(10)
    def get_mount_facts(self):
        self.facts['mounts'] = []
        fstab = get_file_content('/etc/fstab')
        if fstab:
            for line in fstab.split('\n'):
                if line.startswith('#') or line.strip() == '':
                    continue
                fields = re.sub(r'\s+',' ',line.rstrip('\n')).split()
                self.facts['mounts'].append({'mount': fields[1], 'device': fields[0], 'fstype' : fields[2], 'options': fields[3]})

    def get_device_facts(self):
        sysdir = '/dev'
        self.facts['devices'] = {}
        drives = re.compile('(ada?\d+|da\d+|a?cd\d+)') #TODO: rc, disks, err = module.run_command("/sbin/sysctl kern.disks")
        slices = re.compile('(ada?\d+s\d+\w*|da\d+s\d+\w*)')
        if os.path.isdir(sysdir):
            dirlist = sorted(os.listdir(sysdir))
            for device in dirlist:
                d = drives.match(device)
                if d:
                    self.facts['devices'][d.group(1)] = []
                s = slices.match(device)
                if s:
                    self.facts['devices'][d.group(1)].append(s.group(1))

    def get_dmi_facts(self):
        ''' learn dmi facts from system

        Use dmidecode executable if available'''

        # Fall back to using dmidecode, if available
        dmi_bin = module.get_bin_path('dmidecode')
        DMI_DICT = dict(
            bios_date='bios-release-date',
            bios_version='bios-version',
            form_factor='chassis-type',
            product_name='system-product-name',
            product_serial='system-serial-number',
            product_uuid='system-uuid',
            product_version='system-version',
            system_vendor='system-manufacturer'
        )
        for (k, v) in DMI_DICT.items():
            if dmi_bin is not None:
                (rc, out, err) = module.run_command('%s -s %s' % (dmi_bin, v))
                if rc == 0:
                    # Strip out commented lines (specific dmidecode output)
                    self.facts[k] = ''.join([ line for line in out.split('\n') if not line.startswith('#') ])
                    try:
                        json.dumps(self.facts[k])
                    except UnicodeDecodeError:
                        self.facts[k] = 'NA'
                else:
                    self.facts[k] = 'NA'
            else:
                self.facts[k] = 'NA'


class NetBSDHardware(Hardware):
    """
    NetBSD-specific subclass of Hardware.  Defines memory and CPU facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count
    - devices
    """
    platform = 'NetBSD'
    MEMORY_FACTS = ['MemTotal', 'SwapTotal', 'MemFree', 'SwapFree']

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        try:
            self.get_mount_facts()
        except TimeoutError:
            pass
        return self.facts

    def get_cpu_facts(self):

        i = 0
        physid = 0
        sockets = {}
        if not os.access("/proc/cpuinfo", os.R_OK):
            return
        self.facts['processor'] = []
        for line in open("/proc/cpuinfo").readlines():
            data = line.split(":", 1)
            key = data[0].strip()
            # model name is for Intel arch, Processor (mind the uppercase P)
            # works for some ARM devices, like the Sheevaplug.
            if key == 'model name' or key == 'Processor':
                if 'processor' not in self.facts:
                    self.facts['processor'] = []
                self.facts['processor'].append(data[1].strip())
                i += 1
            elif key == 'physical id':
                physid = data[1].strip()
                if physid not in sockets:
                    sockets[physid] = 1
            elif key == 'cpu cores':
                sockets[physid] = int(data[1].strip())
        if len(sockets) > 0:
            self.facts['processor_count'] = len(sockets)
            self.facts['processor_cores'] = reduce(lambda x, y: x + y, sockets.values())
        else:
            self.facts['processor_count'] = i
            self.facts['processor_cores'] = 'NA'

    def get_memory_facts(self):
        if not os.access("/proc/meminfo", os.R_OK):
            return
        for line in open("/proc/meminfo").readlines():
            data = line.split(":", 1)
            key = data[0]
            if key in NetBSDHardware.MEMORY_FACTS:
                val = data[1].strip().split(' ')[0]
                self.facts["%s_mb" % key.lower()] = long(val) / 1024

    @timeout(10)
    def get_mount_facts(self):
        self.facts['mounts'] = []
        fstab = get_file_content('/etc/fstab')
        if fstab:
            for line in fstab.split('\n'):
                if line.startswith('#') or line.strip() == '':
                    continue
                fields = re.sub(r'\s+',' ',line.rstrip('\n')).split()
                self.facts['mounts'].append({'mount': fields[1], 'device': fields[0], 'fstype' : fields[2], 'options': fields[3]})

class AIX(Hardware):
    """
    AIX-specific subclass of Hardware.  Defines memory and CPU facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor (a list)
    - processor_cores
    - processor_count
    """
    platform = 'AIX'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        self.get_dmi_facts()
        return self.facts

    def get_cpu_facts(self):
        self.facts['processor'] = []


        rc, out, err = module.run_command("/usr/sbin/lsdev -Cc processor")
        if out:
            i = 0
            for line in out.split('\n'):

                if 'Available' in line:
                    if i == 0:
                        data = line.split(' ')
                        cpudev = data[0]

                    i += 1
            self.facts['processor_count'] = int(i)

            rc, out, err = module.run_command("/usr/sbin/lsattr -El " + cpudev + " -a type")

            data = out.split(' ')
            self.facts['processor'] = data[1]

            rc, out, err = module.run_command("/usr/sbin/lsattr -El " + cpudev + " -a smt_threads")

            data = out.split(' ')
            self.facts['processor_cores'] = int(data[1])

    def get_memory_facts(self):
        pagesize = 4096
        rc, out, err = module.run_command("/usr/bin/vmstat -v")
        for line in out.split('\n'):
            data = line.split()
            if 'memory pages' in line:
                pagecount = long(data[0])
            if 'free pages' in line:
                freecount = long(data[0])
        self.facts['memtotal_mb'] = pagesize * pagecount / 1024 / 1024
        self.facts['memfree_mb'] = pagesize * freecount / 1024 / 1024
        # Get swapinfo.  swapinfo output looks like:
        # Device          1M-blocks     Used    Avail Capacity
        # /dev/ada0p3        314368        0   314368     0%
        #
        rc, out, err = module.run_command("/usr/sbin/lsps -s")
        if out:
            lines = out.split('\n')
            data = lines[1].split()
            swaptotal_mb = long(data[0].rstrip('MB'))
            percused = int(data[1].rstrip('%'))
            self.facts['swaptotal_mb'] = swaptotal_mb
            self.facts['swapfree_mb'] = long(swaptotal_mb * ( 100 - percused ) / 100)

    def get_dmi_facts(self):
        rc, out, err = module.run_command("/usr/sbin/lsattr -El sys0 -a fwversion")
        data = out.split()
        self.facts['firmware_version'] = data[1].strip('IBM,')

class HPUX(Hardware):
    """
    HP-UX-specifig subclass of Hardware. Defines memory and CPU facts:
    - memfree_mb
    - memtotal_mb
    - swapfree_mb
    - swaptotal_mb
    - processor
    - processor_cores
    - processor_count
    - model
    - firmware
    """

    platform = 'HP-UX'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.get_cpu_facts()
        self.get_memory_facts()
        self.get_hw_facts()
        return self.facts

    def get_cpu_facts(self):
        if self.facts['architecture'] == '9000/800':
            rc, out, err = module.run_command("ioscan -FkCprocessor | wc -l", use_unsafe_shell=True)
            self.facts['processor_count'] = int(out.strip())
        #Working with machinfo mess
        elif self.facts['architecture'] == 'ia64':
            if self.facts['distribution_version'] == "B.11.23":
                rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep 'Number of CPUs'", use_unsafe_shell=True)
                self.facts['processor_count'] = int(out.strip().split('=')[1])
                rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep 'processor family'", use_unsafe_shell=True)
                self.facts['processor'] = re.search('.*(Intel.*)', out).groups()[0].strip()
                rc, out, err = module.run_command("ioscan -FkCprocessor | wc -l", use_unsafe_shell=True)
                self.facts['processor_cores'] = int(out.strip())
            if self.facts['distribution_version'] == "B.11.31":
                #if machinfo return cores strings release B.11.31 > 1204
                rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep core | wc -l", use_unsafe_shell=True)
                if out.strip()== '0':
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep Intel", use_unsafe_shell=True)
                    self.facts['processor_count'] = int(out.strip().split(" ")[0])
                    #If hyperthreading is active divide cores by 2
                    rc, out, err = module.run_command("/usr/sbin/psrset | grep LCPU", use_unsafe_shell=True)
                    data = re.sub(' +',' ',out).strip().split(' ')
                    if len(data) == 1:
                        hyperthreading = 'OFF'
                    else:
                        hyperthreading = data[1]
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep logical", use_unsafe_shell=True)
                    data = out.strip().split(" ")
                    if hyperthreading == 'ON':
                        self.facts['processor_cores'] = int(data[0])/2
                    else:
                        if len(data) == 1:
                            self.facts['processor_cores'] = self.facts['processor_count']
                        else:
                            self.facts['processor_cores'] = int(data[0])
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep Intel |cut -d' ' -f4-", use_unsafe_shell=True)
                    self.facts['processor'] = out.strip()
                else:
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | egrep 'socket[s]?$' | tail -1", use_unsafe_shell=True)
                    self.facts['processor_count'] = int(out.strip().split(" ")[0])
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep -e '[0-9] core' | tail -1", use_unsafe_shell=True)
                    self.facts['processor_cores'] = int(out.strip().split(" ")[0])
                    rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep Intel", use_unsafe_shell=True)
                    self.facts['processor'] = out.strip()

    def get_memory_facts(self):
        pagesize = 4096
        rc, out, err = module.run_command("/usr/bin/vmstat | tail -1", use_unsafe_shell=True)
        data = int(re.sub(' +',' ',out).split(' ')[5].strip())
        self.facts['memfree_mb'] = pagesize * data / 1024 / 1024
        if self.facts['architecture'] == '9000/800':
            try:
                rc, out, err = module.run_command("grep Physical /var/adm/syslog/syslog.log")
                data = re.search('.*Physical: ([0-9]*) Kbytes.*',out).groups()[0].strip()
                self.facts['memtotal_mb'] = int(data) / 1024
            except AttributeError:
                #For systems where memory details aren't sent to syslog or the log has rotated, use parsed
                #adb output. Unfortunatley /dev/kmem doesn't have world-read, so this only works as root.
                if os.access("/dev/kmem", os.R_OK):
                    rc, out, err = module.run_command("echo 'phys_mem_pages/D' | adb -k /stand/vmunix /dev/kmem | tail -1 | awk '{print $2}'", use_unsafe_shell=True)
                    if not err:
                      data = out
                      self.facts['memtotal_mb'] = int(data) / 256
        else:
            rc, out, err = module.run_command("/usr/contrib/bin/machinfo | grep Memory", use_unsafe_shell=True)
            data = re.search('Memory[\ :=]*([0-9]*).*MB.*',out).groups()[0].strip()
            self.facts['memtotal_mb'] = int(data)
        rc, out, err = module.run_command("/usr/sbin/swapinfo -m -d -f -q")
        self.facts['swaptotal_mb'] = int(out.strip())
        rc, out, err = module.run_command("/usr/sbin/swapinfo -m -d -f | egrep '^dev|^fs'", use_unsafe_shell=True)
        swap = 0
        for line in out.strip().split('\n'):
            swap += int(re.sub(' +',' ',line).split(' ')[3].strip())
        self.facts['swapfree_mb'] = swap

    def get_hw_facts(self):
        rc, out, err = module.run_command("model")
        self.facts['model'] = out.strip()
        if self.facts['architecture'] == 'ia64':
            separator = ':'
            if self.facts['distribution_version'] == "B.11.23":
                separator = '='
            rc, out, err = module.run_command("/usr/contrib/bin/machinfo |grep -i 'Firmware revision' | grep -v BMC", use_unsafe_shell=True)
            self.facts['firmware_version'] = out.split(separator)[1].strip()


class Darwin(Hardware):
    """
    Darwin-specific subclass of Hardware.  Defines memory and CPU facts:
    - processor
    - processor_cores
    - memtotal_mb
    - memfree_mb
    - model
    - osversion
    - osrevision
    """
    platform = 'Darwin'

    def __init__(self):
        Hardware.__init__(self)

    def populate(self):
        self.sysctl = self.get_sysctl()
        self.get_mac_facts()
        self.get_cpu_facts()
        self.get_memory_facts()
        return self.facts

    def get_sysctl(self):
        rc, out, err = module.run_command(["/usr/sbin/sysctl", "hw", "machdep", "kern"])
        if rc != 0:
            return dict()
        sysctl = dict()
        for line in out.splitlines():
            if line.rstrip("\n"):
                (key, value) = re.split(' = |: ', line, maxsplit=1)
                sysctl[key] = value.strip()
        return sysctl

    def get_system_profile(self):
        rc, out, err = module.run_command(["/usr/sbin/system_profiler", "SPHardwareDataType"])
        if rc != 0:
            return dict()
        system_profile = dict()
        for line in out.splitlines():
            if ': ' in line:
                (key, value) = line.split(': ', 1)
                system_profile[key.strip()] = ' '.join(value.strip().split())
        return system_profile

    def get_mac_facts(self):
        rc, out, err = module.run_command("sysctl hw.model")
        if rc == 0:
            self.facts['model'] = out.splitlines()[-1].split()[1]
        self.facts['osversion'] = self.sysctl['kern.osversion']
        self.facts['osrevision'] = self.sysctl['kern.osrevision']

    def get_cpu_facts(self):
        if 'machdep.cpu.brand_string' in self.sysctl: # Intel
            self.facts['processor'] = self.sysctl['machdep.cpu.brand_string']
            self.facts['processor_cores'] = self.sysctl['machdep.cpu.core_count']
        else: # PowerPC
            system_profile = self.get_system_profile()
            self.facts['processor'] = '%s @ %s' % (system_profile['Processor Name'], system_profile['Processor Speed'])
            self.facts['processor_cores'] = self.sysctl['hw.physicalcpu']

    def get_memory_facts(self):
        self.facts['memtotal_mb'] = long(self.sysctl['hw.memsize']) / 1024 / 1024

        rc, out, err = module.run_command("sysctl hw.usermem")
        if rc == 0:
            self.facts['memfree_mb'] = long(out.splitlines()[-1].split()[1]) / 1024 / 1024

class Network(Facts):
    """
    This is a generic Network subclass of Facts.  This should be further
    subclassed to implement per platform.  If you subclass this,
    you must define:
    - interfaces (a list of interface names)
    - interface_<name> dictionary of ipv4, ipv6, and mac address information.

    All subclasses MUST define platform.
    """
    platform = 'Generic'

    IPV6_SCOPE = { '0' : 'global',
                   '10' : 'host',
                   '20' : 'link',
                   '40' : 'admin',
                   '50' : 'site',
                   '80' : 'organization' }

    def __new__(cls, *arguments, **keyword):
        subclass = cls
        for sc in Network.__subclasses__():
            if sc.platform == platform.system():
                subclass = sc
        #return super(cls, subclass).__new__(subclass, *arguments, **keyword)
	return super(cls, subclass).__new__(subclass)

    def __init__(self, module):
        self.module = module
        Facts.__init__(self)

    def populate(self):
        return self.facts

class LinuxNetwork(Network):
    """
    This is a Linux-specific subclass of Network.  It defines
    - interfaces (a list of interface names)
    - interface_<name> dictionary of ipv4, ipv6, and mac address information.
    - all_ipv4_addresses and all_ipv6_addresses: lists of all configured addresses.
    - ipv4_address and ipv6_address: the first non-local address for each family.
    """
    platform = 'Linux'

    def __init__(self, module):
        Network.__init__(self, module)

    def populate(self):
        ip_path = self.module.get_bin_path('ip')
        if ip_path is None:
            return self.facts
        default_ipv4, default_ipv6 = self.get_default_interfaces(ip_path)
        interfaces, ips = self.get_interfaces_info(ip_path, default_ipv4, default_ipv6)
        self.facts['interfaces'] = interfaces.keys()
        for iface in interfaces:
            self.facts[iface] = interfaces[iface]
        self.facts['default_ipv4'] = default_ipv4
        self.facts['default_ipv6'] = default_ipv6
        self.facts['all_ipv4_addresses'] = ips['all_ipv4_addresses']
        self.facts['all_ipv6_addresses'] = ips['all_ipv6_addresses']
        return self.facts

    def get_default_interfaces(self, ip_path):
        # Use the commands:
        #     ip -4 route get 8.8.8.8                     -> Google public DNS
        #     ip -6 route get 2404:6800:400a:800::1012    -> ipv6.google.com
        # to find out the default outgoing interface, address, and gateway
        command = dict(
            v4 = [ip_path, '-4', 'route', 'get', '8.8.8.8'],
            v6 = [ip_path, '-6', 'route', 'get', '2404:6800:400a:800::1012']
        )
        interface = dict(v4 = {}, v6 = {})
        for v in 'v4', 'v6':
            if v == 'v6' and self.facts['os_family'] == 'RedHat' \
                and self.facts['distribution_version'].startswith('4.'):
                continue
            if v == 'v6' and not socket.has_ipv6:
                continue
            rc, out, err = module.run_command(command[v])
            if not out:
                # v6 routing may result in
                #   RTNETLINK answers: Invalid argument
                continue
            words = out.split('\n')[0].split()
            # A valid output starts with the queried address on the first line
            if len(words) > 0 and words[0] == command[v][-1]:
                for i in range(len(words) - 1):
                    if words[i] == 'dev':
                        interface[v]['interface'] = words[i+1]
                    elif words[i] == 'src':
                        interface[v]['address'] = words[i+1]
                    elif words[i] == 'via' and words[i+1] != command[v][-1]:
                        interface[v]['gateway'] = words[i+1]
        return interface['v4'], interface['v6']

    def get_interfaces_info(self, ip_path, default_ipv4, default_ipv6):
        interfaces = {}
        ips = dict(
            all_ipv4_addresses = [],
            all_ipv6_addresses = [],
        )

        for path in glob.glob('/sys/class/net/*'):
            if not os.path.isdir(path):
                continue
            device = os.path.basename(path)
            interfaces[device] = { 'device': device }
            if os.path.exists(os.path.join(path, 'address')):
                macaddress = open(os.path.join(path, 'address')).read().strip()
                if macaddress and macaddress != '00:00:00:00:00:00':
                    interfaces[device]['macaddress'] = macaddress
            if os.path.exists(os.path.join(path, 'mtu')):
                interfaces[device]['mtu'] = int(open(os.path.join(path, 'mtu')).read().strip())
            if os.path.exists(os.path.join(path, 'operstate')):
                interfaces[device]['active'] = open(os.path.join(path, 'operstate')).read().strip() != 'down'
#            if os.path.exists(os.path.join(path, 'carrier')):
#                interfaces[device]['link'] = open(os.path.join(path, 'carrier')).read().strip() == '1'
            if os.path.exists(os.path.join(path, 'device','driver', 'module')):
                interfaces[device]['module'] = os.path.basename(os.path.realpath(os.path.join(path, 'device', 'driver', 'module')))
            if os.path.exists(os.path.join(path, 'type')):
                type = open(os.path.join(path, 'type')).read().strip()
                if type == '1':
                    interfaces[device]['type'] = 'ether'
                elif type == '512':
                    interfaces[device]['type'] = 'ppp'
                elif type == '772':
                    interfaces[device]['type'] = 'loopback'
            if os.path.exists(os.path.join(path, 'bridge')):
                interfaces[device]['type'] = 'bridge'
                interfaces[device]['interfaces'] = [ os.path.basename(b) for b in glob.glob(os.path.join(path, 'brif', '*')) ]
                if os.path.exists(os.path.join(path, 'bridge', 'bridge_id')):
                    interfaces[device]['id'] = open(os.path.join(path, 'bridge', 'bridge_id')).read().strip()
                if os.path.exists(os.path.join(path, 'bridge', 'stp_state')):
                    interfaces[device]['stp'] = open(os.path.join(path, 'bridge', 'stp_state')).read().strip() == '1'
            if os.path.exists(os.path.join(path, 'bonding')):
                interfaces[device]['type'] = 'bonding'
                interfaces[device]['slaves'] = open(os.path.join(path, 'bonding', 'slaves')).read().split()
                interfaces[device]['mode'] = open(os.path.join(path, 'bonding', 'mode')).read().split()[0]
                interfaces[device]['miimon'] = open(os.path.join(path, 'bonding', 'miimon')).read().split()[0]
                interfaces[device]['lacp_rate'] = open(os.path.join(path, 'bonding', 'lacp_rate')).read().split()[0]
                primary = open(os.path.join(path, 'bonding', 'primary')).read()
                if primary:
                    interfaces[device]['primary'] = primary
                    path = os.path.join(path, 'bonding', 'all_slaves_active')
                    if os.path.exists(path):
                        interfaces[device]['all_slaves_active'] = open(path).read() == '1'

            # Check whether an interface is in promiscuous mode
            if os.path.exists(os.path.join(path,'flags')):
                promisc_mode = False
                # The second byte indicates whether the interface is in promiscuous mode.
                # 1 = promisc
                # 0 = no promisc
                data = int(open(os.path.join(path, 'flags')).read().strip(),16)
                promisc_mode = (data & 0x0100 > 0)
                interfaces[device]['promisc'] = promisc_mode

            def parse_ip_output(output, secondary=False):
                for line in output.split('\n'):
                    if not line:
                        continue
                    words = line.split()
                    if words[0] == 'inet':
                        if '/' in words[1]:
                            address, netmask_length = words[1].split('/')
                        else:
                            # pointopoint interfaces do not have a prefix
                            address = words[1]
                            netmask_length = "32"
                        address_bin = struct.unpack('!L', socket.inet_aton(address))[0]
                        netmask_bin = (1<<32) - (1<<32>>int(netmask_length))
                        netmask = socket.inet_ntoa(struct.pack('!L', netmask_bin))
                        network = socket.inet_ntoa(struct.pack('!L', address_bin & netmask_bin))
                        iface = words[-1]
                        if iface != device:
                            interfaces[iface] = {}
                        if not secondary and "ipv4" not in interfaces[iface]:
                            interfaces[iface]['ipv4'] = {'address': address,
                                                         'netmask': netmask,
                                                         'network': network}
                        else:
                            if "ipv4_secondaries" not in interfaces[iface]:
                                interfaces[iface]["ipv4_secondaries"] = []
                            interfaces[iface]["ipv4_secondaries"].append({
                                'address': address,
                                'netmask': netmask,
                                'network': network,
                            })

                        # add this secondary IP to the main device
                        if secondary:
                            if "ipv4_secondaries" not in interfaces[device]:
                                interfaces[device]["ipv4_secondaries"] = []
                            interfaces[device]["ipv4_secondaries"].append({
                                'address': address,
                                'netmask': netmask,
                                'network': network,
                            })

                        # If this is the default address, update default_ipv4
                        if 'address' in default_ipv4 and default_ipv4['address'] == address:
                            default_ipv4['netmask'] = netmask
                            default_ipv4['network'] = network
                            default_ipv4['macaddress'] = macaddress
                            default_ipv4['mtu'] = interfaces[device]['mtu']
                            default_ipv4['type'] = interfaces[device].get("type", "unknown")
                            default_ipv4['alias'] = words[-1]
                        if not address.startswith('127.'):
                            ips['all_ipv4_addresses'].append(address)
                    elif words[0] == 'inet6':
                        address, prefix = words[1].split('/')
                        scope = words[3]
                        if 'ipv6' not in interfaces[device]:
                            interfaces[device]['ipv6'] = []
                        interfaces[device]['ipv6'].append({
                            'address' : address,
                            'prefix'  : prefix,
                            'scope'   : scope
                        })
                        # If this is the default address, update default_ipv6
                        if 'address' in default_ipv6 and default_ipv6['address'] == address:
                            default_ipv6['prefix']     = prefix
                            default_ipv6['scope']      = scope
                            default_ipv6['macaddress'] = macaddress
                            default_ipv6['mtu']        = interfaces[device]['mtu']
                            default_ipv6['type']       = interfaces[device].get("type", "unknown")
                        if not address == '::1':
                            ips['all_ipv6_addresses'].append(address)

            ip_path = module.get_bin_path("ip")

            args = [ip_path, 'addr', 'show', 'primary', device]
            rc, stdout, stderr = self.module.run_command(args)
            primary_data = stdout

            args = [ip_path, 'addr', 'show', 'secondary', device]
            rc, stdout, stderr = self.module.run_command(args)
            secondary_data = stdout

            parse_ip_output(primary_data)
            parse_ip_output(secondary_data, secondary=True)

        # replace : by _ in interface name since they are hard to use in template
        new_interfaces = {}
        for i in interfaces:
            if ':' in i:
                new_interfaces[i.replace(':','_')] = interfaces[i]
            else:
                new_interfaces[i] = interfaces[i]
        return new_interfaces, ips

class GenericBsdIfconfigNetwork(Network):
    """
    This is a generic BSD subclass of Network using the ifconfig command.
    It defines
    - interfaces (a list of interface names)
    - interface_<name> dictionary of ipv4, ipv6, and mac address information.
    - all_ipv4_addresses and all_ipv6_addresses: lists of all configured addresses.
    It currently does not define
    - default_ipv4 and default_ipv6
    - type, mtu and network on interfaces
    """
    platform = 'Generic_BSD_Ifconfig'

    def __init__(self, module):
        Network.__init__(self, module)

    def populate(self):

        ifconfig_path = module.get_bin_path('ifconfig')

        if ifconfig_path is None:
            return self.facts
        route_path = module.get_bin_path('route')

        if route_path is None:
            return self.facts

        default_ipv4, default_ipv6 = self.get_default_interfaces(route_path)
        interfaces, ips = self.get_interfaces_info(ifconfig_path)
        self.merge_default_interface(default_ipv4, interfaces, 'ipv4')
        self.merge_default_interface(default_ipv6, interfaces, 'ipv6')
        self.facts['interfaces'] = interfaces.keys()

        for iface in interfaces:
            self.facts[iface] = interfaces[iface]

        self.facts['default_ipv4'] = default_ipv4
        self.facts['default_ipv6'] = default_ipv6
        self.facts['all_ipv4_addresses'] = ips['all_ipv4_addresses']
        self.facts['all_ipv6_addresses'] = ips['all_ipv6_addresses']

        return self.facts

    def get_default_interfaces(self, route_path):

        # Use the commands:
        #     route -n get 8.8.8.8                            -> Google public DNS
        #     route -n get -inet6 2404:6800:400a:800::1012    -> ipv6.google.com
        # to find out the default outgoing interface, address, and gateway

        command = dict(
            v4 = [route_path, '-n', 'get', '8.8.8.8'],
            v6 = [route_path, '-n', 'get', '-inet6', '2404:6800:400a:800::1012']
        )

        interface = dict(v4 = {}, v6 = {})

        for v in 'v4', 'v6':

            if v == 'v6' and not socket.has_ipv6:
                continue
            rc, out, err = module.run_command(command[v])
            if not out:
                # v6 routing may result in
                #   RTNETLINK answers: Invalid argument
                continue
            lines = out.split('\n')
            for line in lines:
                words = line.split()
                # Collect output from route command
                if len(words) > 1:
                    if words[0] == 'interface:':
                        interface[v]['interface'] = words[1]
                    if words[0] == 'gateway:':
                        interface[v]['gateway'] = words[1]

        return interface['v4'], interface['v6']

    def get_interfaces_info(self, ifconfig_path):
        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses = [],
            all_ipv6_addresses = [],
        )
        # FreeBSD, DragonflyBSD, NetBSD, OpenBSD and OS X all implicitly add '-a'
        # when running the command 'ifconfig'.
        # Solaris must explicitly run the command 'ifconfig -a'.
        rc, out, err = module.run_command([ifconfig_path, '-a'])

        for line in out.split('\n'):

            if line:
                words = line.split()

                if words[0] == 'pass':
                    continue
                elif re.match('^\S', line) and len(words) > 3:
                    current_if = self.parse_interface_line(words)
                    interfaces[ current_if['device'] ] = current_if
                elif words[0].startswith('options='):
                    self.parse_options_line(words, current_if, ips)
                elif words[0] == 'nd6':
                    self.parse_nd6_line(words, current_if, ips)
                elif words[0] == 'ether':
                    self.parse_ether_line(words, current_if, ips)
                elif words[0] == 'media:':
                    self.parse_media_line(words, current_if, ips)
                elif words[0] == 'status:':
                    self.parse_status_line(words, current_if, ips)
                elif words[0] == 'lladdr':
                    self.parse_lladdr_line(words, current_if, ips)
                elif words[0] == 'inet':
                    self.parse_inet_line(words, current_if, ips)
                elif words[0] == 'inet6':
                    self.parse_inet6_line(words, current_if, ips)
                else:
                    self.parse_unknown_line(words, current_if, ips)

        return interfaces, ips

    def parse_interface_line(self, words):
        device = words[0][0:-1]
        current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'type': 'unknown'}
        current_if['flags']  = self.get_options(words[1])
        current_if['macaddress'] = 'unknown'    # will be overwritten later

        if len(words) >= 5 : # Newer FreeBSD versions
            current_if['metric'] = words[3]
            current_if['mtu'] = words[5]
        else:
            current_if['mtu'] = words[3]

        return current_if

    def parse_options_line(self, words, current_if, ips):
        # Mac has options like this...
        current_if['options'] = self.get_options(words[0])

    def parse_nd6_line(self, words, current_if, ips):
        # FreBSD has options like this...
        current_if['options'] = self.get_options(words[1])

    def parse_ether_line(self, words, current_if, ips):
        current_if['macaddress'] = words[1]

    def parse_media_line(self, words, current_if, ips):
        # not sure if this is useful - we also drop information
        current_if['media'] = words[1]
        if len(words) > 2:
            current_if['media_select'] = words[2]
        if len(words) > 3:
            current_if['media_type'] = words[3][1:]
        if len(words) > 4:
            current_if['media_options'] = self.get_options(words[4])

    def parse_status_line(self, words, current_if, ips):
        current_if['status'] = words[1]

    def parse_lladdr_line(self, words, current_if, ips):
        current_if['lladdr'] = words[1]

    def parse_inet_line(self, words, current_if, ips):
        address = {'address': words[1]}
        # deal with hex netmask
        if re.match('([0-9a-f]){8}', words[3]) and len(words[3]) == 8:
            words[3] = '0x' + words[3]
        if words[3].startswith('0x'):
            address['netmask'] = socket.inet_ntoa(struct.pack('!L', int(words[3], base=16)))
        else:
            # otherwise assume this is a dotted quad
            address['netmask'] = words[3]
        # calculate the network
        address_bin = struct.unpack('!L', socket.inet_aton(address['address']))[0]
        netmask_bin = struct.unpack('!L', socket.inet_aton(address['netmask']))[0]
        address['network'] = socket.inet_ntoa(struct.pack('!L', address_bin & netmask_bin))
        # broadcast may be given or we need to calculate
        if len(words) > 5:
            address['broadcast'] = words[5]
        else:
            address['broadcast'] = socket.inet_ntoa(struct.pack('!L', address_bin | (~netmask_bin & 0xffffffff)))
        # add to our list of addresses
        if not words[1].startswith('127.'):
            ips['all_ipv4_addresses'].append(address['address'])
        current_if['ipv4'].append(address)

    def parse_inet6_line(self, words, current_if, ips):
        address = {'address': words[1]}
        if (len(words) >= 4) and (words[2] == 'prefixlen'):
            address['prefix'] = words[3]
        if (len(words) >= 6) and (words[4] == 'scopeid'):
            address['scope'] = words[5]
        localhost6 = ['::1', '::1/128', 'fe80::1%lo0']
        if address['address'] not in localhost6:
            ips['all_ipv6_addresses'].append(address['address'])
        current_if['ipv6'].append(address)

    def parse_unknown_line(self, words, current_if, ips):
        # we are going to ignore unknown lines here - this may be
        # a bad idea - but you can override it in your subclass
        pass

    def get_options(self, option_string):
        start = option_string.find('<') + 1
        end = option_string.rfind('>')
        if (start > 0) and (end > 0) and (end > start + 1):
            option_csv = option_string[start:end]
            return option_csv.split(',')
        else:
            return []

    def merge_default_interface(self, defaults, interfaces, ip_type):
        if not 'interface' in defaults.keys():
            return
        if not defaults['interface'] in interfaces:
            return
        ifinfo = interfaces[defaults['interface']]
        # copy all the interface values across except addresses
        for item in ifinfo.keys():
            if item != 'ipv4' and item != 'ipv6':
                defaults[item] = ifinfo[item]
        if len(ifinfo[ip_type]) > 0:
            for item in ifinfo[ip_type][0].keys():
                defaults[item] = ifinfo[ip_type][0][item]

class DarwinNetwork(GenericBsdIfconfigNetwork, Network):
    """
    This is the Mac OS X/Darwin Network Class.
    It uses the GenericBsdIfconfigNetwork unchanged
    """
    platform = 'Darwin'

    # media line is different to the default FreeBSD one
    def parse_media_line(self, words, current_if, ips):
        # not sure if this is useful - we also drop information
        current_if['media'] = 'Unknown' # Mac does not give us this
        current_if['media_select'] = words[1]
        if len(words) > 2:
            current_if['media_type'] = words[2][1:]
        if len(words) > 3:
            current_if['media_options'] = self.get_options(words[3])


class FreeBSDNetwork(GenericBsdIfconfigNetwork, Network):
    """
    This is the FreeBSD Network Class.
    It uses the GenericBsdIfconfigNetwork unchanged.
    """
    platform = 'FreeBSD'

class AIXNetwork(GenericBsdIfconfigNetwork, Network):
    """
    This is the AIX Network Class.
    It uses the GenericBsdIfconfigNetwork unchanged.
    """
    platform = 'AIX'

    # AIX 'ifconfig -a' does not have three words in the interface line
    def get_interfaces_info(self, ifconfig_path):
        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses = [],
            all_ipv6_addresses = [],
        )
        rc, out, err = module.run_command([ifconfig_path, '-a'])

        for line in out.split('\n'):

            if line:
                words = line.split()

		# only this condition differs from GenericBsdIfconfigNetwork
                if re.match('^\w*\d*:', line):
                    current_if = self.parse_interface_line(words)
                    interfaces[ current_if['device'] ] = current_if
                elif words[0].startswith('options='):
                    self.parse_options_line(words, current_if, ips)
                elif words[0] == 'nd6':
                    self.parse_nd6_line(words, current_if, ips)
                elif words[0] == 'ether':
                    self.parse_ether_line(words, current_if, ips)
                elif words[0] == 'media:':
                    self.parse_media_line(words, current_if, ips)
                elif words[0] == 'status:':
                    self.parse_status_line(words, current_if, ips)
                elif words[0] == 'lladdr':
                    self.parse_lladdr_line(words, current_if, ips)
                elif words[0] == 'inet':
                    self.parse_inet_line(words, current_if, ips)
                elif words[0] == 'inet6':
                    self.parse_inet6_line(words, current_if, ips)
                else:
                    self.parse_unknown_line(words, current_if, ips)

        return interfaces, ips

    # AIX 'ifconfig -a' does not inform about MTU, so remove current_if['mtu'] here
    def parse_interface_line(self, words):
        device = words[0][0:-1]
        current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'type': 'unknown'}
        current_if['flags'] = self.get_options(words[1])
        current_if['macaddress'] = 'unknown'    # will be overwritten later
        return current_if

class OpenBSDNetwork(GenericBsdIfconfigNetwork, Network):
    """
    This is the OpenBSD Network Class.
    It uses the GenericBsdIfconfigNetwork.
    """
    platform = 'OpenBSD'

    # Return macaddress instead of lladdr
    def parse_lladdr_line(self, words, current_if, ips):
        current_if['macaddress'] = words[1]

class SunOSNetwork(GenericBsdIfconfigNetwork, Network):
    """
    This is the SunOS Network Class.
    It uses the GenericBsdIfconfigNetwork.

    Solaris can have different FLAGS and MTU for IPv4 and IPv6 on the same interface
    so these facts have been moved inside the 'ipv4' and 'ipv6' lists.
    """
    platform = 'SunOS'

    # Solaris 'ifconfig -a' will print interfaces twice, once for IPv4 and again for IPv6.
    # MTU and FLAGS also may differ between IPv4 and IPv6 on the same interface.
    # 'parse_interface_line()' checks for previously seen interfaces before defining
    # 'current_if' so that IPv6 facts don't clobber IPv4 facts (or vice versa).
    def get_interfaces_info(self, ifconfig_path):
        interfaces = {}
        current_if = {}
        ips = dict(
            all_ipv4_addresses = [],
            all_ipv6_addresses = [],
        )
        rc, out, err = module.run_command([ifconfig_path, '-a'])

        for line in out.split('\n'):

            if line:
                words = line.split()

                if re.match('^\S', line) and len(words) > 3:
                    current_if = self.parse_interface_line(words, current_if, interfaces)
                    interfaces[ current_if['device'] ] = current_if
                elif words[0].startswith('options='):
                    self.parse_options_line(words, current_if, ips)
                elif words[0] == 'nd6':
                    self.parse_nd6_line(words, current_if, ips)
                elif words[0] == 'ether':
                    self.parse_ether_line(words, current_if, ips)
                elif words[0] == 'media:':
                    self.parse_media_line(words, current_if, ips)
                elif words[0] == 'status:':
                    self.parse_status_line(words, current_if, ips)
                elif words[0] == 'lladdr':
                    self.parse_lladdr_line(words, current_if, ips)
                elif words[0] == 'inet':
                    self.parse_inet_line(words, current_if, ips)
                elif words[0] == 'inet6':
                    self.parse_inet6_line(words, current_if, ips)
                else:
                    self.parse_unknown_line(words, current_if, ips)

        # 'parse_interface_line' and 'parse_inet*_line' leave two dicts in the
        # ipv4/ipv6 lists which is ugly and hard to read.
        # This quick hack merges the dictionaries. Purely cosmetic.
        for iface in interfaces:
            for v in 'ipv4', 'ipv6':
                combined_facts = {}
                for facts in interfaces[iface][v]:
                    combined_facts.update(facts)
                if len(combined_facts.keys()) > 0:
                    interfaces[iface][v] = [combined_facts]

        return interfaces, ips

    def parse_interface_line(self, words, current_if, interfaces):
        device = words[0][0:-1]
        if device not in interfaces.keys():
            current_if = {'device': device, 'ipv4': [], 'ipv6': [], 'type': 'unknown'}
        else:
            current_if = interfaces[device]
        flags = self.get_options(words[1])
        v = 'ipv4'
        if 'IPv6' in flags:
            v = 'ipv6'
        current_if[v].append({'flags': flags, 'mtu': words[3]})
        current_if['macaddress'] = 'unknown'    # will be overwritten later
        return current_if

    # Solaris displays single digit octets in MAC addresses e.g. 0:1:2:d:e:f
    # Add leading zero to each octet where needed.
    def parse_ether_line(self, words, current_if, ips):
        macaddress = ''
        for octet in words[1].split(':'):
            octet = ('0' + octet)[-2:None]
            macaddress += (octet + ':')
        current_if['macaddress'] = macaddress[0:-1]

class Virtual(Facts):
    """
    This is a generic Virtual subclass of Facts.  This should be further
    subclassed to implement per platform.  If you subclass this,
    you should define:
    - virtualization_type
    - virtualization_role
    - container (e.g. solaris zones, freebsd jails, linux containers)

    All subclasses MUST define platform.
    """

    def __new__(cls, *arguments, **keyword):
        subclass = cls
        for sc in Virtual.__subclasses__():
            if sc.platform == platform.system():
                subclass = sc
        return super(cls, subclass).__new__(subclass, *arguments, **keyword)

    def __init__(self):
        Facts.__init__(self)

    def populate(self):
        return self.facts

class LinuxVirtual(Virtual):
    """
    This is a Linux-specific subclass of Virtual.  It defines
    - virtualization_type
    - virtualization_role
    """
    platform = 'Linux'

    def __init__(self):
        Virtual.__init__(self)

    def populate(self):
        self.get_virtual_facts()
        return self.facts

    # For more information, check: http://people.redhat.com/~rjones/virt-what/
    def get_virtual_facts(self):
        if os.path.exists("/proc/xen"):
            self.facts['virtualization_type'] = 'xen'
            self.facts['virtualization_role'] = 'guest'
            try:
                for line in open('/proc/xen/capabilities'):
                    if "control_d" in line:
                        self.facts['virtualization_role'] = 'host'
            except IOError:
                pass
            return

        if os.path.exists('/proc/vz'):
            self.facts['virtualization_type'] = 'openvz'
            if os.path.exists('/proc/bc'):
                self.facts['virtualization_role'] = 'host'
            else:
                self.facts['virtualization_role'] = 'guest'
            return

        if os.path.exists('/proc/1/cgroup'):
            for line in open('/proc/1/cgroup').readlines():
                if re.search('/docker/', line):
                    self.facts['virtualization_type'] = 'docker'
                    self.facts['virtualization_role'] = 'guest'
                    return
                if re.search('/lxc/', line):
                    self.facts['virtualization_type'] = 'lxc'
                    self.facts['virtualization_role'] = 'guest'
                    return

        product_name = get_file_content('/sys/devices/virtual/dmi/id/product_name')

        if product_name in ['KVM', 'Bochs']:
            self.facts['virtualization_type'] = 'kvm'
            self.facts['virtualization_role'] = 'guest'
            return

        if product_name == 'RHEV Hypervisor':
            self.facts['virtualization_type'] = 'RHEV'
            self.facts['virtualization_role'] = 'guest'
            return

        if product_name == 'VMware Virtual Platform':
            self.facts['virtualization_type'] = 'VMware'
            self.facts['virtualization_role'] = 'guest'
            return

        bios_vendor = get_file_content('/sys/devices/virtual/dmi/id/bios_vendor')

        if bios_vendor == 'Xen':
            self.facts['virtualization_type'] = 'xen'
            self.facts['virtualization_role'] = 'guest'
            return

        if bios_vendor == 'innotek GmbH':
            self.facts['virtualization_type'] = 'virtualbox'
            self.facts['virtualization_role'] = 'guest'
            return

        sys_vendor = get_file_content('/sys/devices/virtual/dmi/id/sys_vendor')

        # FIXME: This does also match hyperv
        if sys_vendor == 'Microsoft Corporation':
            self.facts['virtualization_type'] = 'VirtualPC'
            self.facts['virtualization_role'] = 'guest'
            return

        if sys_vendor == 'Parallels Software International Inc.':
            self.facts['virtualization_type'] = 'parallels'
            self.facts['virtualization_role'] = 'guest'
            return

        if sys_vendor == 'QEMU':
            self.facts['virtualization_type'] = 'kvm'
            self.facts['virtualization_role'] = 'guest'
            return

        if os.path.exists('/proc/self/status'):
            for line in open('/proc/self/status').readlines():
                if re.match('^VxID: \d+', line):
                    self.facts['virtualization_type'] = 'linux_vserver'
                    if re.match('^VxID: 0', line):
                        self.facts['virtualization_role'] = 'host'
                    else:
                        self.facts['virtualization_role'] = 'guest'
                    return

        if os.path.exists('/proc/cpuinfo'):
            for line in open('/proc/cpuinfo').readlines():
                if re.match('^model name.*QEMU Virtual CPU', line):
                    self.facts['virtualization_type'] = 'kvm'
                elif re.match('^vendor_id.*User Mode Linux', line):
                    self.facts['virtualization_type'] = 'uml'
                elif re.match('^model name.*UML', line):
                    self.facts['virtualization_type'] = 'uml'
                elif re.match('^vendor_id.*PowerVM Lx86', line):
                    self.facts['virtualization_type'] = 'powervm_lx86'
                elif re.match('^vendor_id.*IBM/S390', line):
                    self.facts['virtualization_type'] = 'PR/SM'
                    lscpu = module.get_bin_path('lscpu')
                    if lscpu:
                        rc, out, err = module.run_command(["lscpu"])
                        if rc == 0:
                            for line in out.split("\n"):
                                data = line.split(":", 1)
                                key = data[0].strip()
                                if key == 'Hypervisor':
                                    self.facts['virtualization_type'] = data[1].strip()
                    else:
                        self.facts['virtualization_type'] = 'ibm_systemz'
                else:
                    continue
                if self.facts['virtualization_type'] == 'PR/SM':
                    self.facts['virtualization_role'] = 'LPAR'
                else:
                    self.facts['virtualization_role'] = 'guest'
                return

        # Beware that we can have both kvm and virtualbox running on a single system
        if os.path.exists("/proc/modules") and os.access('/proc/modules', os.R_OK):
            modules = []
            for line in open("/proc/modules").readlines():
                data = line.split(" ", 1)
                modules.append(data[0])

            if 'kvm' in modules:
                self.facts['virtualization_type'] = 'kvm'
                self.facts['virtualization_role'] = 'host'
                return

            if 'vboxdrv' in modules:
                self.facts['virtualization_type'] = 'virtualbox'
                self.facts['virtualization_role'] = 'host'
                return

        # If none of the above matches, return 'NA' for virtualization_type
        # and virtualization_role. This allows for proper grouping.
        self.facts['virtualization_type'] = 'NA'
        self.facts['virtualization_role'] = 'NA'
        return


class HPUXVirtual(Virtual):
    """
    This is a HP-UX specific subclass of Virtual. It defines
    - virtualization_type
    - virtualization_role
    """
    platform = 'HP-UX'

    def __init__(self):
        Virtual.__init__(self)

    def populate(self):
        self.get_virtual_facts()
        return self.facts

    def get_virtual_facts(self):
        if os.path.exists('/usr/sbin/vecheck'):
            rc, out, err = module.run_command("/usr/sbin/vecheck")
            if rc == 0:
                self.facts['virtualization_type'] = 'guest'
                self.facts['virtualization_role'] = 'HP vPar'
        if os.path.exists('/opt/hpvm/bin/hpvminfo'):
            rc, out, err = module.run_command("/opt/hpvm/bin/hpvminfo")
            if rc == 0 and re.match('.*Running.*HPVM vPar.*', out):
                self.facts['virtualization_type'] = 'guest'
                self.facts['virtualization_role'] = 'HPVM vPar'
            elif rc == 0 and re.match('.*Running.*HPVM guest.*', out):
                self.facts['virtualization_type'] = 'guest'
                self.facts['virtualization_role'] = 'HPVM IVM'
            elif rc == 0 and re.match('.*Running.*HPVM host.*', out):
                self.facts['virtualization_type'] = 'host'
                self.facts['virtualization_role'] = 'HPVM'
        if os.path.exists('/usr/sbin/parstatus'):
            rc, out, err = module.run_command("/usr/sbin/parstatus")
            if rc == 0:
                self.facts['virtualization_type'] = 'guest'
                self.facts['virtualization_role'] = 'HP nPar'


class SunOSVirtual(Virtual):
    """
    This is a SunOS-specific subclass of Virtual.  It defines
    - virtualization_type
    - virtualization_role
    - container
    """
    platform = 'SunOS'

    def __init__(self):
        Virtual.__init__(self)

    def populate(self):
        self.get_virtual_facts()
        return self.facts

    def get_virtual_facts(self):
        rc, out, err = module.run_command("/usr/sbin/prtdiag")
        for line in out.split('\n'):
            if 'VMware' in line:
                self.facts['virtualization_type'] = 'vmware'
                self.facts['virtualization_role'] = 'guest'
            if 'Parallels' in line:
                self.facts['virtualization_type'] = 'parallels'
                self.facts['virtualization_role'] = 'guest'
            if 'VirtualBox' in line:
                self.facts['virtualization_type'] = 'virtualbox'
                self.facts['virtualization_role'] = 'guest'
            if 'HVM domU' in line:
                self.facts['virtualization_type'] = 'xen'
                self.facts['virtualization_role'] = 'guest'
        # Check if it's a zone
        if os.path.exists("/usr/bin/zonename"):
            rc, out, err = module.run_command("/usr/bin/zonename")
            if out.rstrip() != "global":
                self.facts['container'] = 'zone'
        # Check if it's a branded zone (i.e. Solaris 8/9 zone)
        if os.path.isdir('/.SUNWnative'):
            self.facts['container'] = 'zone'
        # If it's a zone check if we can detect if our global zone is itself virtualized.
        # Relies on the "guest tools" (e.g. vmware tools) to be installed
        if 'container' in self.facts and self.facts['container'] == 'zone':
            rc, out, err = module.run_command("/usr/sbin/modinfo")
            for line in out.split('\n'):
                if 'VMware' in line:
                    self.facts['virtualization_type'] = 'vmware'
                    self.facts['virtualization_role'] = 'guest'
                if 'VirtualBox' in line:
                    self.facts['virtualization_type'] = 'virtualbox'
                    self.facts['virtualization_role'] = 'guest'

def get_file_content(path, default=None):
    data = default
    if os.path.exists(path) and os.access(path, os.R_OK):
        data = open(path).read().strip()
        if len(data) == 0:
            data = default
    return data

def ansible_facts(module):
    facts = {}
    #facts.update(Facts().populate())
    facts.update(Hardware().populate())
    facts.update(Network(module).populate())
    facts.update(Virtual().populate())
    return facts

if __name__ == "__main__":
    main()
