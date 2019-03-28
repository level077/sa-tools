#! /usr/bin/python

import psutil
from subprocess import PIPE

software = []

def get_version(name=None,cmdline=None,ports=None):
  version = None
  with psutil.Popen(["rpm", '-qf',cmdline], stdout=PIPE,stderr=PIPE) as p:
    p.wait(timeout=1)
    if p.returncode == 0:
      version = p.communicate()[0].strip()
      return version
  if not version:
    if name == 'nginx':
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[1].split("/")[-1].strip()
          return version
    elif name == "redis-server":
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].split("=")[-1].strip()
          return version
    elif name == "etcd":
      with psutil.Popen([cmdline,"-version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].strip()
          return version
    elif name == "mysqld":
      with psutil.Popen([cmdline,"--version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].strip()
          return version
  return "Unknown" 

def get_centos_software():
  for proc in psutil.process_iter(attrs=['name','cmdline','connections']):
    s = {}
    s['name'] = proc.info['name']
    s['listen'] = []
    s['ports'] = []
    cmdline = proc.info['cmdline']
    if len(cmdline) != 0:
      if s['name'] == 'nginx':
        s['cmdline'] = cmdline[3]
      else:
        s['cmdline'] = cmdline[0].split()[0]
    for c in proc.info['connections']:
      if c.status == "LISTEN":
        s['ports'].append(c.laddr.port)
        s['listen'].append(c.laddr.ip + ":" + str(c.laddr.port))
    if len(s['listen']) != 0 and len(s['cmdline']) !=0:
      s['ports'] = list(set(s['ports']))
      s['version'] = get_version(s['name'],s['cmdline'],s['ports'])
      software.append(s)
  return software

if __name__ == "__main__":
  info = get_centos_software()
  print(info)
