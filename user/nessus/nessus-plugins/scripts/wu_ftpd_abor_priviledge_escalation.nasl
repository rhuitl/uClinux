#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: David Greenman <dg at root dot com>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14301);
 script_cve_id("CVE-1999-1326");
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8718");
 script_version ("$Revision: 1.4 $");

 
 name["english"] = "wu-ftpd ABOR Privilege Escalation";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote Wu-FTPd server seems to be vulnerable to a remote privilege 
escalation.

This version contains a flaw that may allow a malicious user to gain
access to unauthorized privileges. 

Specifically, there is a flaw in the way that the server handles
an ABOR command after a data connection has been closed.  The 
flaw is within the dologout() function and proper exploitation
will give the remote attacker the ability to execute arbitrary 
code as the 'root' user.

This flaw may lead to a loss of confidentiality and/or integrity.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.


Solution : Upgrade to Wu-FTPd 2.4.2 or newer

Risk factor : High";
		
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_hole(port);
