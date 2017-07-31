# Copyright 2017 VMware, Inc.  All rights reserved. -- VMware Confidential
# Description: Script for Setting Up NSP on VCF Environment
if __name__ == '__main__':
        if "--nsp_deploy" in sys.argv:
		print "Stage 1: Deploying NSP OVF on VC"
	if "--wait_for_service" in sys.argv:
		print "Stage 2: Waiting for NSP services to come up"
	if "--configure_basic" in sys.argv:
		print "Stage 3: Adding VC, NSX and Proxy details"
	if "--restart_service":
		print "Stage 4: Restarting web and app engine after adding details"
	if "--api_config":
		print "Stage 5: Configuring roles, networks and fleet of NSP"
