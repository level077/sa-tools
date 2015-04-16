import os
import re

OBSOLETE_POPEN = False
try:
    import subprocess
except ImportError:
    import popen2
    OBSOLETE_POPEN = True

import threading
import time

_WorkerThread = None    #Worker thread object
_glock = threading.Lock()   #Synchronization lock
_refresh_rate = 10 #Refresh rate of the netstat data
_host = None
_port = None
_cmd = None
_metric_prefix =None

_status = {}

def redis_status(name):
    '''Return the redis status.'''
    global _WorkerThread
   
    if _WorkerThread is None:
        print 'Error: No netstat data gathering thread created for metric %s' % name
        return 0
        
    if not _WorkerThread.running and not _WorkerThread.shuttingdown:
        try:
            _WorkerThread.start()
        except (AssertionError, RuntimeError):
            pass

    if _WorkerThread.num < 2:
        return 0
    _glock.acquire()
    ret = float(_status[name])
    _glock.release()
    return ret

#create descriptions
def create_desc(skel,prop):
    d = skel.copy()
    for k,v in prop.iteritems():
        d[k] = v
    return d

class NetstatThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.shuttingdown = False
	self.num = 0

    def shutdown(self):
        self.shuttingdown = True
        if not self.running:
            return
        self.join()

    def run(self):
        global _status,sock
   
        tempstatus = _status.copy()
        
        #Set the state of the running thread
        self.running = True
        
        #Continue running until a shutdown event is indicated
        while not self.shuttingdown:
            if self.shuttingdown:
                break
	    
	    if not OBSOLETE_POPEN:
                self.popenChild = subprocess.Popen(_cmd,shell=True,stdout=subprocess.PIPE)
                lines = self.popenChild.communicate()[0].split('\r\n')
            else:
                self.popenChild = popen2.Popen3(_cmd)
                lines = self.popenChild.fromchild.readlines()

            try:
                self.popenChild.wait()
            except OSError, e:
                if e.errno == 10: # No child process
                    continue
            for status in lines:
                # skip empty lines
                if status == '':
                    continue
		if re.match(r'^#',status):
		    continue
		line = status.split(':')
                if line[0] == 'connected_clients':
                    tempstatus[_metric_prefix + 'connected_clients'] = line[1]
   		elif line[0] == 'blocked_clients':
		    tempstatus[_metric_prefix + 'blocked_clients'] = line[1]
          	elif line[0] == 'used_memory':
                    tempstatus[_metric_prefix + 'used_memory'] = float(line[1])/1024/1024
		elif line[0] == 'used_memory_rss':
                    tempstatus[_metric_prefix + 'used_memory_rss'] = float(line[1])/1024/1024
		elif line[0] == 'mem_fragmentation_ratio':
                    tempstatus[_metric_prefix + 'mem_fragmentation_ratio'] = line[1]
		elif line[0] == 'total_commands_processed':
                    tempstatus[_metric_prefix + 'total_commands_processed'] = line[1]
                    tempstatus[_metric_prefix + 'total_commands_processed_delta'] = (int(line[1])- int(_status[_metric_prefix + 'total_commands_processed']))/_refresh_rate
                elif line[0] == 'evicted_keys':
                    tempstatus[_metric_prefix + 'evicted_keys'] = line[1]
		    tempstatus[_metric_prefix + 'evicted_keys_delta'] = (int(line[1]) - int(_status[_metric_prefix + 'evicted_keys']))/_refresh_rate
                elif line[0] == 'keyspace_misses':
                    tempstatus[_metric_prefix + 'keyspace_misses'] = line[1]
		    tempstatus[_metric_prefix + 'keyspace_misses_delta'] = (int(line[1]) - int(_status[_metric_prefix + 'keyspace_misses']))/_refresh_rate
		elif line[0] == 'used_cpu_sys':
                    tempstatus[_metric_prefix + 'used_cpu_sys'] = line[1]
                    tempstatus[_metric_prefix + 'used_cpu_sys_delta'] = (float(line[1]) - float(_status[_metric_prefix + 'used_cpu_sys']))/_refresh_rate
		elif line[0] == 'used_cpu_user':
                    tempstatus[_metric_prefix + 'used_cpu_user'] = line[1]
                    tempstatus[_metric_prefix + 'used_cpu_user_delta'] = (float(line[1]) - float(_status[_metric_prefix + 'used_cpu_user']))/_refresh_rate
		elif line[0] == 'used_cpu_sys_children':
                    tempstatus[_metric_prefix + 'used_cpu_sys_children'] = line[1]
                    tempstatus[_metric_prefix + 'used_cpu_sys_children_delta'] = (float(line[1]) - float(_status[_metric_prefix + 'used_cpu_sys_children']))/_refresh_rate
		elif line[0] == 'used_cpu_user_children':
                    tempstatus[_metric_prefix + 'used_cpu_user_children'] = line[1]
                    tempstatus[_metric_prefix + 'used_cpu_user_children_delta'] = (float(line[1]) - float(_status[_metric_prefix + 'used_cpu_user_children']))/_refresh_rate
		elif line[0] == 'db0':
                    tempstatus[_metric_prefix + 'db0'] = line[1].split('=')[1].split(',')[0]
                        
            #Acquire a lock and copy the temporary connection state dictionary
            # to the global state dictionary.
            _glock.acquire()
            for tmpstatus in _status:
                _status[tmpstatus] = tempstatus[tmpstatus]
            _glock.release()
            
            #Wait for the refresh_rate period before collecting the netstat data again.
            if not self.shuttingdown:
                time.sleep(_refresh_rate)

	    self.num += 1
            if self.num >= 2:
                self.num = 2
            
        #Set the current state of the thread after a shutdown has been indicated.
        self.running = False

def metric_init(params):
    global _cmd,_metric_prefix, _refresh_rate, _WorkerThread, _host, _port, _status,descriptors
    
    #Read the refresh_rate from the gmond.conf parameters.
    if 'RefreshRate' in params:
        _refresh_rate = int(params['RefreshRate'])

    if 'Host' in params:
        _host = params['Host']
  
    if 'Port' in params:
	_port = params['Port']

    if 'Redis-cli' in params:
	_cmd = params['Redis-cli'] + " -h " + _host + " -p " + _port + " info"
    else:
	_cmd = "redis-cli -h " + _host + " -p " + _port + " info"

    _metric_prefix = "redis_"+_host + "_" + _port + "_"

    _status = {_metric_prefix +'connected_clients': 0,
        _metric_prefix + 'blocked_clients':0,
        _metric_prefix + 'used_memory':0,
        _metric_prefix + 'used_memory_rss':0,
        _metric_prefix + 'mem_fragmentation_ratio':0,
        _metric_prefix + 'total_commands_processed':0,
        _metric_prefix + 'total_commands_processed_delta':0,
        _metric_prefix + 'evicted_keys':0,
        _metric_prefix + 'evicted_keys_delta':0,
        _metric_prefix + 'keyspace_misses':0,
        _metric_prefix + 'keyspace_misses_delta':0,
        _metric_prefix + 'used_cpu_sys':0,
        _metric_prefix + 'used_cpu_sys_delta':0,
	_metric_prefix + 'used_cpu_user':0,
	_metric_prefix + 'used_cpu_user_delta':0,
	_metric_prefix + 'used_cpu_sys_children':0,
	_metric_prefix + 'used_cpu_sys_children_delta':0,
	_metric_prefix + 'used_cpu_user_children':0,
	_metric_prefix + 'used_cpu_user_children_delta':0,
	_metric_prefix + 'db0':0}

    #create descriptors
    descriptors = []
    
    Desc_Skel = {
        'name'        : 'XXX',
        'call_back'   : redis_status,
        'time_max'    : 30,
        'value_type'  : 'float',
        'format'      : '%.2f',
        'units'       : 'XXX',
        'slope'       : 'both', # zero|positive|negative|both
	'description' : 'http://redis.io/commands/info',
        'groups'      : 'redis'+ _host + '_' + _port,
        }

    descriptors.append(create_desc(Desc_Skel,{
			'name': _metric_prefix + 'connected_clients',
			'units': 'count',
			})) 
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'blocked_clients',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_memory',
                        'units': 'M',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_memory_rss',
                        'units': 'M',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'mem_fragmentation_ratio',
                        'units': '%',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'total_commands_processed_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'evicted_keys_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'keyspace_misses_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_cpu_sys_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_cpu_user_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_cpu_sys_children_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'used_cpu_user_children_delta',
                        'units': 'count',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'db0',
                        'units': 'count',
                        }))
    
    #Start the worker thread
    _WorkerThread = NetstatThread()
    
    #Return the metric descriptions to Gmond
    return descriptors

def metric_cleanup():
    '''Clean up the metric module.'''
    
    #Tell the worker thread to shutdown
    _WorkerThread.shutdown()

#This code is for debugging and unit testing    
if __name__ == '__main__':
    params = {'RefreshRate': '2','Host':'192.168.0.1',"Port":"6379"}
    metric_init(params)
    while True:
        try:
            for d in descriptors:
                v = d['call_back'](d['name'])
                print 'value for %s is %.2f' % (d['name'],  v)
            time.sleep(2)
        except KeyboardInterrupt:
            os._exit(1)
