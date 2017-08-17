import socket
import shutil
from subprocess import call
import sys,getopt

def get_system_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	my_ip = s.getsockname()[0]
	s.close()
	return my_ip

def vpn_changes(zip_name,destination,user):
	# change the VPN file
	my_ip = get_system_ip()
	# 1. add config
	f = "/root/VPN-files/client.ovpn"
	new_conf = "push \"redirectl-gateway def1\"\n"
	dir_name = "/root/VPN-files"
	# change the IP
	with open(f,"r+") as fd:
		lines = fd.readlines()
		if not new_conf in lines:
			lines.append(new_conf) # add new conf file as well
		fd.seek(0)
		for line in lines:
			if "remote" in line:
				# change the IP
				s = "remote %s 1194\n" % (my_ip)
				fd.write(s)
			else:
				fd.write(line)

	# also change the server config and restart the VPN-Server
	shutil.make_archive(zip_name, 'zip', dir_name)

	# move file to destination ip
	cmd = "scp %s %s@%s:" % ("%s.zip"%zip_name, user, destination)
	call(cmd.split())
	# give password and done

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
	print "usage:", "vpn_setup.py [ -z | --zip_name ] <zip name> [ -d | --dest ] <destination host> [ -u | --user ] <username>"
	print "                    [ -h | --help ] Open help menu"

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
	config_file = dest = username = ""
	if argc < 4:
		print "Insufficient Arguments !"
		usage()
		sys.exit()
	try:
		opts,args = getopt.getopt(argv[1:],"hz:d:u:",["zip_name=","help","dest=","user="])
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	# basic test done, check for options
	for opt,arg in opts:
		if opt in ('-h',"--help"):
			usage()
			sys.exit()
		elif opt in ("-z","--zip_name"):
			if ".zip" in arg:
				print "Please don't give an extension! We will take care of it!"
				sys.exit()
			config_file = arg
		elif opt in ("-d","--dest"):
			dest = arg
		elif opt in ("-u","--user"):
			username = arg
	return config_file,dest,username

if __name__ == '__main__':
	zip_name,destination,username = parseInputCommand(len(sys.argv),sys.argv)
	# TODO: add validation here
	print "zip name: ",zip_name," destination_host: ",destination, " username: ",username
	vpn_changes(zip_name,destination,username)
