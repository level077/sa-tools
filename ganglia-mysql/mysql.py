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
_port = None
_cmd = None

#Global dictionary storing the counts of the last mysql status
# read from the show global status output
_status = {'queries': 0,
	'queries_delta':0,
	'insert':0,
	'insert_delta':0,
	'select':0,
	'select_delta':0,
	'update':0,
	'update_delta':0,
	'delete':0,
	'delete_delta':0,
	'created_tmp_disk_tables':0,
	'created_tmp_disk_tables_delta':0,
	'created_tmp_files':0,
	'created_tmp_files_delta':0,
	'created_tmp_tables':0,
	'created_tmp_tables_delta':0,
        'threads_connected': 0,
        'threads_running':0,
	'innodb_pool_read_hit':0,
	'innodb_pool_read_hit_delta':0,
	'innodb_pool_read_requests':0,
	'innodb_pool_read_requests_delta':0,
	'innodb_pool_reads':0,
	'innodb_pool_reads_delta':0}

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
            
            #Iterate through the show global status output 
            for status in lines:
                # skip empty lines
                if status == '':
                    continue

                line = status.split()
                if line[0] == 'Queries':
                    tempstatus['queries'] = line[1]
		    tempstatus['queries_delta'] = (int(line[1])- int(_status['queries']))/_refresh_rate
   		elif line[0] == 'Com_select':
		    tempstatus['select'] = line[1]
		    tempstatus['select_delta'] = (int(line[1])- int(_status['select']))/_refresh_rate
          	elif line[0] == 'Com_insert':
                    tempstatus['insert'] = line[1]
                    tempstatus['insert_delta'] = (int(line[1])- int(_status['insert']))/_refresh_rate
		elif line[0] == 'Com_update':
                    tempstatus['update'] = line[1]
                    tempstatus['update_delta'] = (int(line[1])- int(_status['update']))/_refresh_rate
		elif line[0] == 'Com_delete':
                    tempstatus['delete'] = line[1]
                    tempstatus['delete_delta'] = (int(line[1])- int(_status['delete']))/_refresh_rate
		elif line[0] == 'Created_tmp_disk_tables':
                    tempstatus['created_tmp_disk_tables'] = line[1]
                    tempstatus['created_tmp_disk_tables_delta'] = (int(line[1])- int(_status['created_tmp_disk_tables']))/_refresh_rate
		elif line[0] == 'Created_tmp_files':
                    tempstatus['created_tmp_files'] = line[1]
                    tempstatus['created_tmp_files_delta'] = (int(line[1])- int(_status['created_tmp_files']))/_refresh_rate
		elif line[0] == 'Created_tmp_tables':
                    tempstatus['created_tmp_tables'] = line[1]
                    tempstatus['created_tmp_tables_delta'] = (int(line[1])- int(_status['created_tmp_tables']))/_refresh_rate
                elif line[0] == 'Threads_connected':
                    tempstatus['threads_connected'] = line[1]
                elif line[0] == 'Threads_running':
                    tempstatus['threads_running'] = line[1]
		elif line[0] == 'Innodb_buffer_pool_read_requests':
                    tempstatus['innodb_pool_read_requests'] = line[1]
                    tempstatus['innodb_pool_read_requests_delta'] = int(line[1]) - int(_status['innodb_pool_read_requests'])
                elif line[0] == 'Innodb_buffer_pool_reads':
                    tempstatus['innodb_pool_reads'] = line[1]
                    tempstatus['innodb_pool_reads_delta'] = int(line[1]) - int(_status['innodb_pool_reads'])

            tempstatus['innodb_pool_read_hit'] = 1 - float(tempstatus['innodb_pool_reads'])/float(tempstatus['innodb_pool_read_requests'])
            tempstatus['innodb_pool_read_hit_delta'] = 1 - float(tempstatus['innodb_pool_reads_delta'])/float(tempstatus['innodb_pool_read_requests_delta'])
                        
            #Acquire a lock and copy the temporary status dictionary
            # to the global status dictionary.
            _glock.acquire()
            for tmpstatus in _status:
                _status[tmpstatus] = tempstatus[tmpstatus]
            _glock.release()
            
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
    global _refresh_rate, _WorkerThread, _host, _port, _user, _password, _cmd, descriptors
    
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

    #create descriptors
    descriptors = []
    
    Desc_Skel = {
        'name'        : 'XXX',
        'call_back'   : mysql_status,
        'time_max'    : 30,
        'value_type'  : 'float',
        'format'      : '%.3f',
        'units'       : 'XXX',
        'slope'       : 'both', # zero|positive|negative|both
        'description' : 'XXX',
        'groups'      : 'mysql_'+ _host + '_' + _port,
        }

    descriptors.append(create_desc(Desc_Skel,{
			'name': 'queries_delta',
			'units': 'count/s',
			'description': 'mysql queries',
			})) 
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'select_delta',
                        'units': 'count/s',
                        'description': 'select_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'update_delta',
                        'units': 'count/s',
                        'description': 'update_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'delete_delta',
                        'units': 'count/s',
                        'description': 'delete_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'insert_delta',
                        'units': 'count/s',
                        'description': 'insert_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'created_tmp_disk_tables_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_disk_tables_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'created_tmp_tables_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_tables_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'created_tmp_files_delta',
                        'units': 'count/s',
                        'description': 'created_tmp_files_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'threads_connected',
                        'units': 'count',
                        'description': 'thread_connected',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'threads_running',
                        'units': 'count',
                        'description': 'threads_running',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'innodb_pool_read_hit',
                        'units': '%',
                        'description': 'innodb_pool_read_hit',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': 'innodb_pool_read_hit_delta',
                        'units': '%',
                        'description': 'innodb_pool_read_hit_delta',
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
    params = {'RefreshRate': '2','Host':'192.168.10.1',"Port":"3306","User":"xxxx","Password":"xxxxx"}
    metric_init(params)
    while True:
        try:
            for d in descriptors:
                v = d['call_back'](d['name'])
                print 'value for %s is %.3f' % (d['name'],  v)
            time.sleep(2)
        except KeyboardInterrupt:
            os._exit(1)
