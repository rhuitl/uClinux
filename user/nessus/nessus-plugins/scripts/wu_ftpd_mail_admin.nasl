#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Adam Zabrocki <pi3ki31ny@wp.pl>
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14371);
 script_bugtraq_id(8668);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"2594");
 script_version ("$Revision: 1.3 $");

 
 name["english"] = "wu-ftpd MAIL_ADMIN overflow";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote Wu-FTPd server seems to be vulnerable to a remote flaw.

This version fails to properly check bounds on a pathname when Wu-Ftpd is 
compiled with MAIL_ADMIN enabled resulting in a buffer overflow. With a 
specially crafted request, an attacker can possibly execute arbitrary code 
as the user Wu-Ftpd runs as (usually root) resulting in a loss of integrity, 
and/or availability.

It should be noted that this vulnerability is not present within the default 
installation of Wu-Ftpd. 

The server must be configured using the 'MAIL_ADMIN' option to notify an 
administrator when a file has been uploaded.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.

Solution : Upgrade to Wu-FTPd 2.6.3 when available
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

if(egrep(pattern:".*wu-2\.6\.[012].*", string:banner))
	security_hole(port);

