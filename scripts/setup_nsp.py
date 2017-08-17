#!/usr/bin/python
# Copyright 2017 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Script for Setting Up NSP on VCF Environment

"""
TODO: Put url of the confluence page, any architecture diagrams
1. Reporting Log
2. replace prints with development logs
3. Add Resume/Skip feature - Useful when the process dies, API fails and you want to change and build up something :)
"""

import json
import sys,getopt
import time
from subprocess import call
import base64
import ssh
import urllib3
import datetime

def get_package(package_name):
	cmd = "apt-get install python-%s" % (package_name)
	call(cmd.split())

class SSH_Client(object):
	
	hostname = None
	username = None
	password = None
	root_pwd = None
	__conn = None

	def __init__(self,host,username,password,root_pwd=None):
		self.hostname = host
		self.username = username
		self.password = password
		self.root_pwd = root_pwd

	def _connection(self):
		if not self.__conn:
			self.__conn = ssh.SSH(self.hostname, self.username, self.password)
		return self.__conn

	def execute_command(self,cmd,is_root):
		print "Running command: %s" % (cmd)
		if is_root:
			self._connection().switch_user_exec_cmd(self.root_pwd, cmd)
			return
		stdout, stderr, exit_status = self._connection().cmd(cmd)
		return stdout

class NSP_Setup(object):
	"""docstring for NSP_Setup"""
	config = None
	http = None
	host = None
	username = None
	password = None
	common_headers = {
		"Accept": "application/json",
		"Content-Type": "application/json"
	}
	VC_params = None
	x_hm_token = None
	container_deployment_id = None

	def __init__(self, config):
		self.config = config
		self.create_pool_manager()
		self.VC_params = config['VC']
		self.host = self.config["NSP"]['common']["host"]
		self.username = self.config["NSP"]['common']["username"]
		self.password = self.config["NSP"]['common']["password"]

	def __del__(self):
		self.config = None
		self.http = None

	def create_pool_manager(self):
		self.http = urllib3.PoolManager(timeout = 30.0)

	def call(self,url,headers,body,method = "GET"):
		# TODO - error checks utility
		try:
			body_encoded = json.dumps(body).encode('utf-8')
			headers.update(self.common_headers)
			#if "session" in url:
			#	headers.update({"Content-Type":"application/x-www-form-urlencoded"})
			print "url: %s\nheaders: %s\nbody: %s\n" % (url,headers,body_encoded) 
			r = self.http.request(
					method,
					url,
					body=body_encoded,
					headers=headers
				)
			print "response: ","STATUS: ",r.status," DATA: ",r.data.decode('utf-8')
			# status check
			if r.status not in [200,201,202,203,204,205,206]:
				print "Response status: %s ! Desired status code: 2XX" % (r.status)
				sys.exit()

			return r
		except urllib3.exceptions.MaxRetryError,e:
			print "[ERROR]: %s " % (str(e))
			sys.exit()
		except Exception,e:
			print "[ERROR]: %s " % (str(e))
			sys.exit(2)

	def parse_common_parameters(self):
		# TODO: parameter validations !! 
		self.host = self.config['NSP']['host']
		self.username = self.config['NSP']['username']
		self.password = self.config['NSP']['password']
		self.VC_params = self.config['VC']

	def add_vc(self,username,password,vc_json,host):
		print "[BASIC] 1. Adding VC to NSP VM"
		auth_params = "%s:%s" % (username,password)
		url = "https://%s:9443/api/admin/global/config/vcenter" % (host)
		body = {
			"data": {
				"items": [{
					"config": {
						"url": "https://%s" % (vc_json['host']),
						"userName": vc_json['username'],
						"password": base64.b64encode(self.vc_json['password'])
					}
				}]
			}
		}
		headers = urllib3.util.make_headers(basic_auth=auth_params)
		self.call(url, headers, body, "POST")

	def add_nsx(self):
		print "[BASIC] 2. Adding NSX to NSP VM"
		auth_params = "%s:%s" % (self.username,self.password)
		url = "https://%s:9443/api/admin/global/config/nsx" % (self.host)
		body = {
			"data": {
				"items": [{
					"config": {
						"url": "https://%s" % (self.config['NSX']['host']),
						"userName": self.config['NSX']['username'],
						"password": base64.b64encode(self.config['NSX']['password'])
					}
				}]
			}
		}
		headers = urllib3.util.make_headers(basic_auth=auth_params)
		self.call(url, headers, body, "POST")

	def add_sso(self,username,password,lookup_json,host):
		print "[BASIC] 3. Adding SSO to NSP VM"
		auth_params = "%s:%s" % (username,password)
		url = "https://%s:9443/api/admin/global/config/lookupservice" % (self.host)
		body = {
			"data": {
				"items": [{
					"config": {
						"lookupServiceUrl": self.config['LOOKUP']['service_url'],
						"providerType": self.config['LOOKUP']['provider_type'],
						"ssoDomain": self.config['LOOKUP']['sso_domain']
					}
				}]
			}
		}
		headers = urllib3.util.make_headers(basic_auth=auth_params)
		self.call(url, headers, body, "POST")

	def add_nsp(self):
		print "[BASIC] 4. Adding proxy to NSP VM"
		auth_params = "%s:%s" % (self.username,self.password)
		url = "https://%s:9443/api/admin/global/config/nsp" % (self.host)
		body = {
			"data": {
				"items": [{
					"config": {
						"baseProxyUrl": self.config['NSP']['basic']['proxy'],
						"extensibilityExchange": self.config['NSP']['basic']['ipam_exchange'],
						"cloudType": self.config['NSP']['basic']['cloud_type'],
						"isVcdGatewaysEnabled": self.config['NSP']['basic']['vcd_enabled'],
						"isDefault": self.config['NSP']['basic']['is_default']
					}
				}]
			}
		}
		headers = urllib3.util.make_headers(basic_auth=auth_params)
		self.call(url, headers, body, "POST")

	def get_session_token(self):
		# make a call to get a new session and check for it
		retry = 0
		while retry < 5:
			print "Retry to get session token: %s"  % (retry)
			self.get_session()
			if self.x_hm_token:
				break
			retry += 1
		if not self.x_hm_token:
			print "[ERROR] Max retries reached. Unable to get a session token. Please ensure VC and NSP are behaving well!"
			sys.exit()

	def hdmz_config(self):
		print "1. HDMZ Config: ",
		#url = "https://%s:9443/api/admin/hybridity/hdmz/config" % (self.host)
		url = "https://%s:8443/admin/hybridity/api/global/config" % (self.host)
		auth_params = "%s:%s" % (self.username,self.password)
		body = {
			"replicationMode" : "UNICAST_MODE"
		}
		# make headers
		#headers = urllib3.util.make_headers(basic_auth=auth_params)
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		self.call(url, headers, body, "PUT")

	def config_role(self):
		# TODO move the values to config file later
		print "2. Config role:"
		url = "https://%s:9443/api/admin/global/config/role" % (self.host)
		body = [{
		    "role": "System Administrator",
		    "userGroups": ["vsphere.local\\Administrators"]
		}, {
		    "role": "Enterprise Administrator",
		    "userGroups": ["vsphere.local\\Administrators"]
		}]
		response_obj = self.call(url, {}, body, "POST")

	def get_session(self):
		print "3. GET SESSION TOKEN: ",
		url = "https://%s:8443/hybridity/api/sessions" % (self.host)
		
		# need VC credentials for getting a session token
		body = {
			"authType": "password",
			"username": self.VC_params['username'],
			"password": self.VC_params['password']
		}
		response_obj = self.call(url, {}, body, "POST")
		# get response x-hm-authorization token from here
		self.x_hm_token = response_obj.getheader('x-hm-authorization')

	def set_license(self):
		print "4. SETTING LICENCSE ",
		if not self.x_hm_token:
			self.get_session_token()

		url = "https://%s:8443/admin/hybridity/api/licenses" % (self.host)
		body = {
			'features': [
				'DHCP',
				'NAT',
				'FIREWALL',
				'IPSEC_VPN',
				'LB',
				'DYNAMIC_ROUTING',
				'STATIC_ROUTING',
				'SSL_VPN',
				'L2_VPN',
				'DFW',
				'WAN_OPTIMIZATION',
				'L2_EXTENSION',
				'LOW_DOWNTIME_MIGRATION',
				'ZERO_DOWNTIME_MIGRATION',
				'POLICY_MIGRATION',
				'PROXIMITY_ROUTING',
				'THROUGHPUT_MULTI_GIGABIT'
			]
		}
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		self.call(url, headers, body, "PUT")

	def deployContainter(self,name,isGlobal):
		print "5. Deploying Containers: ",
		# TODO : Add datastore,resource pool as a list in the config
		url = "https://%s:8443/admin/hybridity/api/global/deploymentContainers" % (self.host)
		body = {
			'datastores': [self.config['NSP']['container']['datastore']],
			'folder': self.config['NSP']['container']['folder'],
			'isGlobal': isGlobal,
			'name': name,
			'resourcePools': [self.config['NSP']['container']['resource_pool']],
			'vCenterInstanceUuid': self.config['VC']['uuid']
		}
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		resp = self.call(url, headers, body, "POST")
		# need to get deployment container id
		resp_data = json.loads(resp.data.decode('utf-8'))
		if isGlobal:
			self.container_deployment_id = resp_data['id']

	def setup_networks(self):
		print "6. Setup Networks: ",
		url = "https://%s:8443/admin/hybridity/api/networks" % (self.host)
		body = self.config["NSP"]["networks"]
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		resp = self.call(url, headers, body, "POST")

	def fleet_site_config(self):
		print "7. Fleet Deployment: ",
		url = "https://%s:8443/admin/hybridity/api/fleetConfig" % (self.host)
		body = self.config["NSP"]["fleet_site"]
		body["deploymentContainerId"] = self.container_deployment_id
		body["rowType"] = "site"
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		resp = self.call(url, headers, body, "POST")

	def fleet_resource_config(self):
		print "7. Fleet Deployment: ",
		url = "https://%s:8443/hybridity/api/fleetConfig/resource/%s" % (self.host, self.config['VC']['uuid'])
		body = self.config["NSP"]["fleet_resource"]
		body['deploymentContainerId'] = self.container_deployment_id
		body['rowType'] = "resource"
		body['resourceId'] = self.config['VC']['uuid']
		body.update({"deploymentContainerId":self.container_deployment_id})
		headers = {
			"x-hm-authorization": self.x_hm_token
		}
		resp = self.call(url, headers, body, "POST")

def restart_services(ssh_cli):
	print "Restarting Web and app engine !"
	stop_web_cmd = "systemctl stop web-engine"
	stop_app_cmd = "systemctl stop app-engine"
	start_web_cmd = "systemctl start web-engine"
	start_app_cmd = "systemctl start app-engine"
	
	# Restart services 
	ssh_cli.execute_command(stop_web_cmd,True)
	ssh_cli.execute_command(stop_app_cmd,True)
	ssh_cli.execute_command(start_web_cmd,True)
	ssh_cli.execute_command(start_app_cmd,True)
	print "Restarted the Engines !"
	time.sleep(30)

def update_certificate(ssh_cli):
	# TODO: change command there
	temp = 1

def get_SiteID_from_NSP(ssh_cli,nsp_obj):
	cmd = "cat /common/location"
	stdout = ssh_cli.execute_command(cmd,False)
	nsp_obj.config['NSP']['fleet_site']['siteId'] = stdout.strip()
	nsp_obj.config['NSP']['fleet_resource']['siteId'] = stdout.strip()

def setup_basic(nsp_obj):
	# Basic Steps
	cfg = nsp_obj.config
	nsp_obj.add_vc(cfg['NSP']['common']['username'],
		cfg['NSP']['common']['password'],cfg['VC'],cfg['NSP']['common']['host'])
	nsp_obj.add_nsx()
	nsp_obj.add_sso(cfg['NSP']['common']['username'],
		cfg['NSP']['common']['password'],cfg['LOOKUP'],
		cfg['NSP']['common']['host'])
	nsp_obj.add_nsp()

def setup_basic_hcm(nsp_obj):
	#Basic step configuration between
	nsp_obj.add_vc(cfg['HCM']['common']['username'],
		cfg['HCM']['common']['password'],cfg['HCM']['VC'],
		cfg['HCM']['common']['host'])
	nsp_obj.add_sso(cfg['HCM']['common']['username'],
		cfg['HCM']['common']['password'],cfg['HCM']['LOOKUP'],
		cfg['HCM']['common']['host'])

def restart_main(nsp_obj):
	ssh_cli = SSH_Client(nsp_obj.config['NSP']['common']['host'],nsp_obj.config['NSP']['common']['username'],nsp_obj.config['NSP']['common']['password'],nsp_obj.config['NSP']['common'].get('root_password'))
	restart_services(ssh_cli)

def setup_main(nsp_obj):
	ssh_cli = SSH_Client(nsp_obj.config['NSP']['common']['host'],nsp_obj.config['NSP']['common']['username'],nsp_obj.config['NSP']['common']['password'],nsp_obj.config['NSP']['common'].get('root_password'))

	nsp_obj.get_session()
	nsp_obj.hdmz_config()
	nsp_obj.config_role()
	nsp_obj.set_license()
	nsp_obj.deployContainter(nsp_obj.config['NSP']['container']['global_name'],
		True)
	nsp_obj.deployContainter(nsp_obj.config['NSP']['container']['local_name'],
		False)
	nsp_obj.setup_networks()
	print "Please update the deployment container id and also the siteID in the config"
	# TODO - Use the ssh file to get the siteID and update the json automatically
	get_SiteID_from_NSP(ssh_cli,nsp_obj)
	nsp_obj.fleet_site_config()
	# Historically, there has been issues with external and mgmt networks being
	# present in the same network. Create a new dvs port group if you face any issue for the same
	nsp_obj.fleet_resource_config()
	print "Add gateways from the U.I for this time, automate this soon as well"
	print "Congratulations, you have configured NSP"
	print "Steps to follow"

# stage 1
def deployOVF(nsp_obj,deploy_json,vc_json,auth_json):
	"""
	For ex - 
	auth_json = cfg['NSP']['common']
	deploy_json = cfg['HCM']['deploy']
	vc_json = cfg['VC']
	"""
	# TODO: add validations
	cmd = ("%s"
	 	" --vService:installation=com.vmware.vim.vsm:extension_vservice"
	 	" --prop:mgr_root_passwd=%s"
	 	" --X:connectionReconnectDelayDouble"
	 	" --diskMode=thin"
	 	" --skipManifestCheck "
	 	" --X:connectionReconnectDelay=1000 "
	 	" --prop:hostname=%s"
	 	" --vmFolder=%s"
	 	" --prop:mgr_ip_0=%s"
	 	" --prop:mgr_dns_list=%s"
	 	" --prop:mgr_cli_passwd=%s"
	 	" --datastore=%s"
	 	" --prop:mgr_prefix_ip_0=%s"
	 	" --prop:mgr_isSSHEnabled=True"
	 	" --overwrite"
	 	" --network=%s"
	 	" --powerOn"
	 	" --name=%s"
	 	" --X:enableHiddenProperties"
	 	" --noSSLVerify"
	 	" --acceptAllEulas"
	 	" --prop:mgr_gateway_0=%s"
	 	" --machineOutput"
	 	" --X:connectionRetryCount=10"
	 	" --ipAllocationPolicy=dhcpPolicy"
	 	" --prop:password=%s"
	 	" --prop:mgr_ntp_list=%s"
	 	" --prop:enable_sshd=True"
	 	" %s" # abs path of the ovf file
	 	"  vi://%s:%s@%s/%s/host/%s/Resources") % (
	 		deploy_json["ovftool_exe_path"],
	 		auth_json["password"],
	 		deploy_json["hostname"],
	 		deploy_json["vm_folder"],
	 		auth_json["host"],
	 		deploy_json["dns"],
	 		auth_json["password"],
	 		deploy_json["datastore"],
	 		deploy_json["prefix"],
	 		deploy_json["network"],
	 		deploy_json["vm_name"],
	 		deploy_json["gateway"],
	 		auth_json["password"],
	 		deploy_json["ntp"],
	 		deploy_json["ovf_path"],
	 		vc_json["username"],
	 		vc_json["password"],
	 		vc_json["host"],
	 		vc_json["datacenter_name"],
	 		vc_json["cluster_name"]
	 	)
	print cmd,"\n"
	call(cmd.split())

def parseConfigFile(config_file):
	"""
	parseConfigFile
		Inputs
			@config_file (str) - Location of the config file
		Description
			Parses the config file,
			Setup the NSP Setup object with the required parameters
		Return 
			@nsp_obj (NSP_Setup) - initialised nsp object
	"""
	config = None
	try:
		with open(config_file) as fd:
			config = json.load(fd)
	except Exception,e:
		print "Error reading file:\n%s" % str(e)
		sys.exit()
	
	# config present now
	nsp_obj = NSP_Setup(config)
	return nsp_obj

def usage():
	"""
	usage:
		Inputs
			None
		Description
			Prints usage of the command line parameters
		Return
			void
	"""
	print ""
	print "usage:", "setup_nsp.py [ -c | --config ] <config file location>"
	print "                    [--nsp_deploy]"
	print ""

def parseInputCommand(argc,argv):
	"""
	parseInputCommand: 
		Inputs
			@argc (int)  - Number of arguments provided
			@argv (list) - List of the given arguments
		Description
			Parses command line parameters, Raise error on invalid arguments,
			Read configuration files and setup the config parameters
		Return
			@config_file (str) - Location of config file
	"""
	config_file = ""

	if argc < 2:
		print "Insufficient Arguments !"
		usage()
		sys.exit()
	try:
		opts,args = getopt.getopt(argv[1:],"hc:d",["config=","help",
			"nsp_deploy","wait_for_service","configure_basic","restart_service",
			"api_config","hcm_deploy","hcm_wait_for_service"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	# basic test done, check for options
	for opt,arg in opts:
		if opt == '-h':
			usage()
			sys.exit()
		elif opt in ("-c","--config"):
			config_file = arg
	return config_file

## UTILITY FUNCTIONS
def dummy_commits(stage):
	msg = "Current commit %s" % (stage)
	cmd = "git commit --allow-empty -m %s" % (msg)
	call(cmd.split())

def check_service_running(url):
	print "Sleeping for 100 seconds to allow for booting"
	time.sleep(100)
	max_error_count = 10
	error_count = 0
	while True and error_count < max_error_count:
		try:
			c = urllib3.HTTPSConnectionPool(url, port=443, cert_reqs='CERT_NONE',
                                assert_hostname=False)
			r = c.request("GET","/")
			if r.status == 403:
				# By default the service is forbidden on root
				break
			time.sleep(10)
		except urllib3.exceptions.MaxRetryError,e:
			print "[MAX-TRY-ERROR]: %s " % (str(e))
			error_count += 1
			time.sleep(10)
		except Exception,e:
			print "[OTHER-ERROR]: %s " % (str(e))
			error_count += 1
			time.sleep(10)
	
	print "Service running now !!"

if __name__ == '__main__':
	"""
	1. Sequencing series of steps to deploy and configure NSP and HCM

	#TODO
	1. Make wait_for_service a common service
	2. generalise nsp_obj to support HCM side params as well
	"""
	print "Test Hello"
	config_file = parseInputCommand(len(sys.argv),sys.argv)
	nsp_obj = parseConfigFile(config_file)
	cfg = nsp_obj.config
	if "--nsp_deploy" in sys.argv:
		print "Stage 1: Deploying NSP OVF on VC"
		deployOVF(nsp_obj,cfg['NSP']['deploy'],cfg['VC'],cfg['NSP']['common'])
	if "--wait_for_service" in sys.argv:
		print "Stage 2: Waiting for NSP services to come up"
		#url = "https://%s" % nsp_obj.config['NSP']['common']['host']
		url = nsp_obj.config['NSP']['common']['host']
		check_service_running(url)
		time.sleep(30) # sleeping extra few seconds for buffer
	if "--configure_basic" in sys.argv:
		print "Stage 3: Adding VC, NSX and Proxy details"
		setup_basic(nsp_obj)
	if "--restart_service" in sys.argv:
		print "Stage 4: Restarting web and app engine after adding details"
		restart_main(nsp_obj)
	if "--api_config" in sys.argv:
		print "Stage 5: Configuring roles, networks and fleet of NSP"
		setup_main(nsp_obj)
	if "--hcm_deploy" in sys.argv:
		deployOVF(nsp_obj,cfg['HCM']['deploy'],cfg['HCM']['VC'],cfg['HCM']['common'])
	if "--hcm_wait_for_service" in sys.argv:
		url = nsp_obj.config['HCM']['common']['host']
		check_service_running(url)
		time.sleep(30) # sleeping extra few seconds for buffer
	if "--hcm_basic_config" in sys.argv:
		setup_basic_hcm(nsp_obj)
