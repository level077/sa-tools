#! /usr/bin/python

import psutil
from subprocess import PIPE
import rpm
import errno

process = []
software = {}

def get_software():
  ts = rpm.TransactionSet()
  mi = ts.dbMatch()
  for h in mi:
    if software.has_key(h['name']):
      version = h[rpm.RPMTAG_VERSION] + "-" + h[rpm.RPMTAG_RELEASE]
      if version not in software[h['name']]["version"]:
        software[h['name']]["version"].append(version)
    else:
      software[h['name']] = {"version": [h[rpm.RPMTAG_VERSION] + "-" + h[rpm.RPMTAG_RELEASE]]}

def get_version(name=None,cmdline=None,ports=None):
  try:
    version = "Unknown"
    with psutil.Popen(["rpm", '-qf',cmdline], stdout=PIPE,stderr=PIPE) as p:
      p.wait(timeout=10)
      if p.returncode == 0:
        #version = p.communicate()[0].strip()
        #return version
        return
    if name == 'nginx':
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=10)
        if p.returncode == 0:
          version = p.communicate()[1].split("/")[-1].strip()
          #return version
    elif name == "redis-server":
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=10)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].split("=")[-1].strip()
          #return version
    elif name == "etcd":
      with psutil.Popen([cmdline,"-version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=10)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].strip()
          #return version
    elif name == "mysqld":
      with psutil.Popen([cmdline,"--version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=10)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].strip()
          #return version
    elif name == "java":
      with psutil.Popen([cmdline,"-version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=10)
        if p.returncode == 0:
          version = p.communicate()[1].split('"')[1].strip()
          #return version
  except OSError as e:
    if e.errno == errno.ENOENT:
        version = 'File not found'
    elif e.errno == errno.EACCES:
        version = 'Permission denied'
    else:
        version = ('Unexpected error: %d', e.errno)
  if software.has_key(name):
    if version not in software[name]["version"]:
      software[name]["version"].append(version)
  else:
    software[name] = {"version": [version] }

def get_centos_process():
  for proc in psutil.process_iter(attrs=['pid','name','cmdline','connections','create_time','username','ppid','exe','status']):
    s = {}
    s['name'] = proc.info['name']
    s['exe'] = proc.info['exe']
    s['username'] = proc.info['username']
    s['create_time'] = proc.info['create_time']
    s['pid'] = proc.info['pid']
    s['status'] = proc.info['status']
    try:
      s['parent'] = psutil.Process(proc.info['ppid']).name()
    except psutil.NoSuchProcess:
      s['parent'] = 'NA'
    s['listen'] = []
    s['ports'] = []
    s['cmdline'] = ' '.join(proc.info['cmdline'])
    for c in proc.info['connections']:
      if c.status == "LISTEN":
        s['ports'].append(c.laddr.port)
        s['listen'].append(c.laddr.ip)
    s['ports'] = tuple(set(s['ports']))
    s['listen'] = tuple(set(s['listen']))
    if len(s['cmdline']) != 0:
      get_version(s['name'],s['exe'],s['ports'])
      process.append(s)
  #return [dict(t) for t in set([tuple(d.items()) for d in software])]
  #get_software()
  #return process, software

def get_info():
  get_centos_process()
  get_software()
  return process, software

if __name__ == "__main__":
  pinfo, sinfo = get_info()
  import json
  #print(json.dumps(sinfo))
  print(json.dumps(pinfo))
