import requests
import json
import base64
#import re
import logging as log

from datetime import timedelta
from datetime import datetime
from datetime import date
from datetime import timezone
from termcolor import colored

class BackendSession:
	BACKEND           = 'https://backend.mapertech.com'
	TESTING 			= 'https://testing.mapertech.com'
	LOGIN             = '/api/login/token/'
	REFRESH           = '/api/login/token/refresh/'
	TREE              = '/api/model/tree/'
	NODE              = '/api/model/node/get/'
	MEASUREMENT_RANGE = '/api/model/measurements/get/'
	MEASUREMENT_INFO  = '/api/model/measurements/info/'
	ALARM_LIST        = '/api/alarms/list/'
	ALARM_EVENTS      = '/api/alarms/events/'
	EVENTS 			= '/api/event/'

	def __init__(self,  user=None, password=None,verbose=False):
		self.s = requests.Session()
		self.tree = None
		self.refresh_token = None
		self.access_token = None
		self.access_expire_time = None
		self.login_time = None
		self.session_expire_time = None

		if verbose:
			log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
			log.info("Verbose output.")
		else:
			log.basicConfig(format="%(levelname)s: %(message)s",level=log.CRITICAL)
			log.info("This should not be printed.")

		if user is not None and password is not None:
        	self.login(user,password)

  	def login(self, user, password):
    	response = self.s.post(BackendSession.BACKEND + BackendSession.LOGIN,
    		data = {'username': user, 'password': password})
    	if response:
        	response = response.json()
        	self.refresh_token =  response['refresh']
        	self.access_token =  response['access']
        	self.login_time = int(datetime.now().timestamp());
        	self.access_expire_time = json.loads(base64.b64decode(self.access_token.split('.')[1]))['exp']-100  # 30 seconds margin
        	self.session_expire_time = json.loads(base64.b64decode(self.refresh_token.split('.')[1]+'==='))['exp']
        	print(f"Successful login. Time until expire: {str(timedelta(seconds=self.session_expire_time-self.login_time))}")

        	self.getTree()

    	else:
        	print("login() - HTTP %i - %s, Message %s" % (response.status_code, response.reason, response.text))  

  	def refresh(self):
    	if self.isExpired():
      	response = self.s.post(BackendSession.BACKEND + BackendSession.REFRESH, 
      							data = {'refresh': self.refresh_token},
                             	headers = {'Authorization': f'Maper {self.access_token}'})
      	if response:
      		response = response.json()
          	self.access_token =  response['access'];
          	self.access_expire_time = json.loads(base64.b64decode(self.access_token.split('.')[1]))['exp']-100  # 30 seconds margin
          	print(f"Acces token refreshed. Time until expire: {timedelta(seconds=self.access_expire_time-datetime.now().timestamp())}")
      	else:
          	print("refresh() - HTTP %i - %s, Message %s" % (response.status_code, response.reason, response.text))  

  	def isExpired(self):
    	if self.access_expire_time is None:
    		print("Session is not loged in")
    		return True
    	else:
      		return int(datetime.now().timestamp())>self.access_expire_time

  	def getTree(self):
    	self.refresh()
    	r = self.s.get(BackendSession.BACKEND + BackendSession.TREE,
                   headers = {'Authorization': f'Maper {self.access_token}'})
    	if r:
    		self.tree = r.json()['data']
    	else:
    		print("getTree() - HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))

  	def getNode(self,nodeId):
    	self.refresh()
    	r = self.s.get(BackendSession.BACKEND + BackendSession.NODE,
    	               params = {'node_id': nodeId},
    	               headers = {'Authorization': f'Maper {self.access_token}'})
    	if r:
    	    return r.json()['data']
    	else:
    	    print("getNode() - HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))
    	    return None

  	def getEvents(self, nodeId, minDate, maxDate):
    	self.refresh()
    	r = self.s.get(BackendSession.BACKEND + BackendSession.EVENTS,
    	               params = {'node': nodeId,'min_date': minDate.isoformat(), 'max_date': maxDate.isoformat()},
    	               headers = {'Authorization': f'Maper {self.access_token}'})
    	if r:
    		return r.json()['data']
    	else:
    		print("getEvents() - HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))

  	def getMeasurements(self, nodeId, minDate, maxDate):
    	self.refresh()
    	r = self.s.get(BackendSession.BACKEND + BackendSession.MEASUREMENT_RANGE,
    	               params = {'node_id': nodeId,'min_date': minDate.isoformat(), 'max_date': maxDate.isoformat()},
    	               headers = {'Authorization': f'Maper {self.access_token}'})
    	if r:
    		return r.json()['data']
    	else:
    		print("getMeasurements() - HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))

  	def getMeasurement(self, measId):
    	self.refresh()
    	r = self.s.get(BackendSession.BACKEND + BackendSession.MEASUREMENT_INFO,
    	               params ={'measurement_id': measId},
    	               headers={'Authorization': f'Maper {self.access_token}'})
    	if r:
    		return r.json()['data']
    	else:
    		print("getMeasurement() - HTTP %i - %s, Message %s" % (r.status_code, r.reason, r.text))    

  	def getMeasurementCooked(self, measId):    
    	meas = session.getMeasurement(measId);
    	domain = meas['info']['domain']
    	measurement = np.frombuffer(base64.b64decode(meas['raw_data'][domain]['acceleration']), dtype=np.float32)
    	if domain=='time':
    		freq = meas['info']['measurement_parameters']['fs']
    		N = meas['info']['measurement_parameters']['samples']
    	else:
    		freq = meas['info']['measurement_parameters']['fmax']
    		N = meas['info']['measurement_parameters']['lines']
    	return measurement,domain,freq,N
      
  	def printTree(self,id=None):
    	if self.tree is None:
    		self.getTree()
    	node = getSubtree(self.tree,aId=id)
    	printTree(node) if node is not None else print('ID not found!')

	def getChildren(self,id=None):
		if self.tree is None:
			self.getTree()
		subtree = getSubtree(self.tree,aId=id)
		return [(f"{children['id']}: {children['name']}",children['id']) for children in subtree['children']]

	def getSubtree(self,id):
		if self.tree is None:
			self.getTree()
		return getSubtree(self.tree,aId=id)

	def traverseTree(self,id,func):
	    if self.tree is None:
	    	self.getTree()

	    node = getSubtree(self.tree,aId=id)

	    if node is not None:
	    	traverseTree(node,func)
	    else:
	    	print('ID not found!')
	  

	def getIncosistentEvents(self, nodeId, minDate, maxDate):
		events = self.getEvents(nodeId, minDate, maxDate)
		inconsistentEvs = []
		falseHelathChange = []

		for i,ev in enumerate(events):
			if i != 0:
				if ev['prev_health'] != events[i-1]['new_health']:
					inconsistentEvs += [ev]
				else:
					# Checkear que la health no sea Observacion, esos se ignoran
					if (ev['new_health'] < events[i-1]['new_health']) and (ev['date']-events[i-1]['date'] < 5MIN):
						falseHelathChange += [ev]

		return inconsistentEvs+falseHelathChange




















def traverseTree(aTree, func,aIndent=0,**kwargs):

	func(aTree,**kwargs)
  
  	# Traverse all node's children
  	if aTree['children']:
    	for child in aTree['children']:
      		traverseTree(child,func,aIndent+4)
    

def getSubtree(aTree, aId=None,aIndent=0,vervose=False):

	# Not looking something in particular, return entire tree  
	if aId is None:
		return aTree
	  
	# Return subtree in case node id matches
	if aId is aTree['id']:
		log.info(" "*aIndent + f"Standing on: {aTree['id']}: {aTree['name']}. Node found!")
		return aTree
	else:
		log.info(" "*aIndent + f"Standing on: {aTree['id']}: {aTree['name']}. Looking for {aId}")

	# If it does not match, traverse all node's children
	if aTree['children']:
		for child in aTree['children']:
	  		subNode = getSubtree(child,aId,aIndent+4)
	  			if subNode is not None:
	    			return subNode # and subNode['id'] is aId else None
				else:
					return None


def printTree(aTree,aIndent=0):
	colors = {'GROUP': 'red',
	        'MACHINE': 'green',
	        'MEASUREMENT_POINT': 'magenta',
        	'SENSOR': 'blue'}

	c = colors[aTree['type']]
	node_id = colored(aTree['id'],c)
	node_name = colored(aTree['name'], c, attrs=['bold'])
	node_type = colored(aTree['type'],c)
	print(' '*aIndent + node_id + ': '+ node_name + '   ['+ node_type + ']')

	for node in aTree['children']:
		printTree(node,aIndent+4)

def printMeasurements(measurements):
	for i in range(len(measurements['dates'])):
    date = datetime.fromtimestamp(measurements['dates'][i]/1000)
    id = measurements['measurements_ids'][i]
    origin = measurements['origin'][i]

    string = f"{date} | ID: {id} | [{origin}]"
    print(colored(string,'magenta'))

    for key in measurements['data']:
    	print(colored(f"    {key}={measurements['data'][key][i]} ",'blue'))

def printMeasurement(json,indents=0):
	for key in json:
		if isinstance(json[key],dict):
			print(' '*indents + colored(f"{key}:",'red',attrs=['bold']))
			printMeasurement(json[key],indents+4)
    	else:
    		if key=='date':
    			value = datetime.fromtimestamp(json[key]/1000)
    		else:
    			value = json[key]
    		print(' '*indents + colored(f"{key}:",'red',attrs=['bold']) + colored(f"{value}",attrs=['bold']))

