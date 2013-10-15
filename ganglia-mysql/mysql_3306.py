import os

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
_user = None
_cmd = None
_metric_prefix =None

#Global dictionary storing the counts of the last mysql status
# read from the show global status output
_status = {}

def mysql_status(name):
    '''Return the mysql status.'''
    global _WorkerThread
   
    if _WorkerThread is None:
        print 'Error: No netstat data gathering thread created for metric %s' % name
        return 0
        
    if not _WorkerThread.running and not _WorkerThread.shuttingdown:
        try:
            _WorkerThread.start()
        except (AssertionError, RuntimeError):
            pass

    #Read the last status for the state requested. The metric
    # name passed in matches the dictionary slot for the state value.

    #ignore the first mysql status
    if _WorkerThread.num < 2:
        return 0
    _glock.acquire()
    ret = int(_status[name])
    _glock.release()
    return ret

#create descriptions
def create_desc(skel,prop):
    d = skel.copy()
    for k,v in prop.iteritems():
        d[k] = v
    return d

class NetstatThread(threading.Thread):
    '''This thread continually gathers the current states of the tcp socket
    connections on the machine.  The refresh rate is controlled by the 
    RefreshRate parameter that is passed in through the gmond.conf file.'''

    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.shuttingdown = False
        self.popenChild = None
	self.num = 0

    def shutdown(self):
        self.shuttingdown = True
        if self.popenChild != None:
            try:
                self.popenChild.wait()
            except OSError, e:
                if e.errno == 10: # No child processes
                    pass

        if not self.running:
            return
        self.join()

    def run(self):
        global _status, _refresh_rate, _cmd
   
        tempstatus = _status.copy()
        
        #Set the state of the running thread
        self.running = True
        
        #Continue running until a shutdown event is indicated
        while not self.shuttingdown:
            if self.shuttingdown:
                break
            
            if not OBSOLETE_POPEN:
                self.popenChild = subprocess.Popen(_cmd,shell=True,stdout=subprocess.PIPE)
                lines = self.popenChild.communicate()[0].split('\n')
            else:
                self.popenChild = popen2.Popen3(_cmd)
                lines = self.popenChild.fromchild.readlines()

            try:
                self.popenChild.wait()
            except OSError, e:
                if e.errno == 10: # No child process
                    continue
            
            #Iterate through the netstat output looking for the 'tcp' keyword in the tcp_at 
            # position and the state information in the tcp_state_at position. Count each 
            # occurance of each state.
            for status in lines:
                # skip empty lines
                if status == '':
                    continue

                line = status.split()
                if line[0] == 'Queries':
                    tempstatus[_metric_prefix + 'queries'] = line[1]
		    tempstatus[_metric_prefix + 'queries_delta'] = (int(line[1])- int(_status[_metric_prefix + 'queries']))/_refresh_rate
   		elif line[0] == 'Com_select':
		    tempstatus[_metric_prefix + 'select'] = line[1]
		    tempstatus[_metric_prefix + 'select_delta'] = (int(line[1])- int(_status[_metric_prefix + 'select']))/_refresh_rate
          	elif line[0] == 'Com_insert':
                    tempstatus[_metric_prefix + 'insert'] = line[1]
                    tempstatus[_metric_prefix + 'insert_delta'] = (int(line[1])- int(_status[_metric_prefix + 'insert']))/_refresh_rate
		elif line[0] == 'Com_update':
                    tempstatus[_metric_prefix + 'update'] = line[1]
                    tempstatus[_metric_prefix + 'update_delta'] = (int(line[1])- int(_status[_metric_prefix + 'update']))/_refresh_rate
		elif line[0] == 'Com_delete':
                    tempstatus[_metric_prefix + 'delete'] = line[1]
                    tempstatus[_metric_prefix + 'delete_delta'] = (int(line[1])- int(_status[_metric_prefix + 'delete']))/_refresh_rate
		elif line[0] == 'Created_tmp_disk_tables':
                    tempstatus[_metric_prefix + 'created_tmp_disk_tables'] = line[1]
                    tempstatus[_metric_prefix + 'created_tmp_disk_tables_delta'] = (int(line[1])- int(_status[_metric_prefix + 'created_tmp_disk_tables']))/_refresh_rate
		elif line[0] == 'Created_tmp_files':
                    tempstatus[_metric_prefix + 'created_tmp_files'] = line[1]
                    tempstatus[_metric_prefix + 'created_tmp_files_delta'] = (int(line[1])- int(_status[_metric_prefix + 'created_tmp_files']))/_refresh_rate
		elif line[0] == 'Created_tmp_tables':
                    tempstatus[_metric_prefix + 'created_tmp_tables'] = line[1]
                    tempstatus[_metric_prefix + 'created_tmp_tables_delta'] = (int(line[1])- int(_status[_metric_prefix + 'created_tmp_tables']))/_refresh_rate
                elif line[0] == 'Threads_connected':
                    tempstatus[_metric_prefix + 'threads_connected'] = line[1]
                elif line[0] == 'Threads_running':
                    tempstatus[_metric_prefix + 'threads_running'] = line[1]
                        
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
    '''Initialize the tcp connection status module and create the
    metric definition dictionary object for each metric.'''
    global _metric_prefix, _refresh_rate, _WorkerThread, _host, _port, _user, _password, _cmd, _status,descriptors
    
    #Read the refresh_rate from the gmond.conf parameters.
    if 'RefreshRate' in params:
        _refresh_rate = int(params['RefreshRate'])

    if 'Host' in params:
        _host = params['Host']
  
    if 'Port' in params:
	_port = params['Port']
 
    if 'User' in params:
        _user = params['User']

    if 'Password' in params:
        _password = params['Password']

    _cmd = "/usr/local/mysql/bin/mysql -u" + _user + " -h" + _host + " -P" + _port + " -p" + _password + " -e 'show global status'" 
    _metric_prefix = _host + "_" + _port + "_"

    _status = {_metric_prefix +'queries': 0,
        _metric_prefix +'queries_delta':0,
        _metric_prefix + 'insert':0,
        _metric_prefix + 'insert_delta':0,
        _metric_prefix + 'select':0,
        _metric_prefix + 'select_delta':0,
        _metric_prefix + 'update':0,
        _metric_prefix + 'update_delta':0,
        _metric_prefix + 'delete':0,
        _metric_prefix + 'delete_delta':0,
        _metric_prefix + 'created_tmp_disk_tables':0,
        _metric_prefix + 'created_tmp_disk_tables_delta':0,
        _metric_prefix + 'created_tmp_files':0,
        _metric_prefix + 'created_tmp_files_delta':0,
        _metric_prefix + 'created_tmp_tables':0,
        _metric_prefix + 'created_tmp_tables_delta':0,
        _metric_prefix + 'threads_connected': 0,
        _metric_prefix + 'threads_running':0}

    #create descriptors
    descriptors = []
    
    Desc_Skel = {
        'name'        : 'XXX',
        'call_back'   : mysql_status,
        'time_max'    : 30,
        'value_type'  : 'uint',
        'format'      : '%u',
        'units'       : 'XXX',
        'slope'       : 'both', # zero|positive|negative|both
        'description' : 'XXX',
        'groups'      : 'mysql '+ _host + '_' + _port,
        }

    descriptors.append(create_desc(Desc_Skel,{
			'name': _metric_prefix + 'queries_delta',
			'units': 'count/s',
			'description': 'mysql queries',
			})) 
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'select_delta',
                        'units': 'count/s',
                        'description': 'select_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'update_delta',
                        'units': 'count/s',
                        'description': 'update_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'delete_delta',
                        'units': 'count/s',
                        'description': 'delete_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'insert_delta',
                        'units': 'count/s',
                        'description': 'insert_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'created_tmp_disk_tables_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_disk_tables_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'created_tmp_tables_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_tables_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'created_tmp_files_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_files_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'threads_connected',
                        'units': 'count',
                        'description': 'thread_connected',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'threads_running',
                        'units': 'count',
                        'description': 'threads_running',
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
    params = {'RefreshRate': '2','Host':'192.168.0.200',"Port":"3306","User":"xxxx","Password":"xxxxxx"}
    metric_init(params)
    while True:
        try:
            for d in descriptors:
                v = d['call_back'](d['name'])
                print 'value for %s is %u' % (d['name'],  v)
            time.sleep(2)
        except KeyboardInterrupt:
            os._exit(1)
