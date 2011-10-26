#
# This script was written by Douglas Minderhout <dminderhout@layer3com.com>
# This script is based on a previous script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to: H D Moore
# 
#
# See the Nessus Scripts License for details
#
#
# Ref: 
# Message-ID: <1043650912.3e34d960788ac@webmail.web-sale.dk>
# Date: Mon, 27 Jan 2003 08:01:52 +0100
# Subject: [VulnWatch] Multiple vulnerabilities found in PlatinumFTPserver V1.0.7
# 

if(description){
 script_id(11200);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "Platinum FTP Server";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
Platinum FTP server for Win32 has several vulnerabilities in 
the way it checks the format of command strings passed to it. 
This leads to the following vulnerabilities in the server:

The 'dir' command can be used to examine the filesystem of the machine and
gather further information about the host by using relative directory listings 
(I.E. '../../../' or '\..\..\..').

The 'delete' command can be used to delete any file on the server that the
Platinum FTP server has permissions to.

Issuing the command  'cd @/..@/..' will cause the 
Platinum FTP server to crash and consume all available CPU time on 
the server.

*** Warning : Nessus solely relied on the banner of this server, so
*** this may be a false positive
		

Solution : see http://www.platinumftp.com/platinumftpserver.php
Risk factor : High";
		 
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks if the remote ftp server is a vulnerable version of Platinum FTP");

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003 Douglas Minderhout");
		  
 script_dependencies("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);
if(banner) {
	if(egrep(pattern:"^220.*PlatinumFTPserver V1\.0\.[0-7][^0-9].*$",string:banner)) {
 		
  		security_hole(port);
   	}
}
