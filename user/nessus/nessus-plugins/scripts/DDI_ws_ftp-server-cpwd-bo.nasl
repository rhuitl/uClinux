#
# Copyright 2002 by Digital Defense, Inc. 
# Author: Forrest Rae <forrest.rae@digitaldefense.net>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#
# Reference: www.atstake.com/research/advisories/2002/a080802-1.txt
# 


if(description)
{
	script_id(11098);
	script_bugtraq_id(5427);
	script_version ("$Revision: 1.9 $");
	script_cve_id("CVE-2002-0826");
	name["english"] = "WS_FTP SITE CPWD Buffer Overflow";
	script_name(english:name["english"]);
	desc["english"] = "
This host is running a version of WS_FTP FTP server prior to 3.1.2.  
Versions earlier than 3.1.2 contain an unchecked buffer in routines that 
handle the 'CPWD' command arguments.  The 'CPWD' command allows remote 
users to change their password.  By issuing a malformed argument to the 
CPWD command, a user could overflow a buffer and execute arbitrary code 
on this host.  Note that a local user account is required.

The vendor has released a patch that fixes this issue.  Please install 
the latest patch available from the vendor's website at 
http://www.ipswitch.com/support/.

Risk factor : High";
		 
	script_description(english:desc["english"]);
	script_summary(english:"Checks FTP server banner for vulnerable version of WS_FTP Server");
	script_category(ACT_GATHER_INFO); 
	script_family(english:"FTP");
	script_copyright(english:"This script is Copyright (C) 2002 Digital Defense, Inc.");
	script_dependencie("find_service_3digits.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

#
# The script code starts here : 
#

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port))exit(0);

banner = get_kb_item(string("ftp/banner/", port));

if(!banner)
{ 
	soc = open_sock_tcp(port);
	if(!soc)exit(0);
	banner = recv_line(socket:soc, length:4096);
}

if(banner)
{
	if(egrep(pattern:".*WS_FTP Server (((1|2)\..*)|(3\.((0(\..*){0,1})|(1\.1))))", string:banner))
	    		security_hole(port:port);		
}

