#
# (C) Tenable Network Security
#

if(description)
{
 script_id(11849);
 script_bugtraq_id(8679);
 script_version ("$Revision: 1.3 $");
 name["english"] = "ProFTPd ASCII upload overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is running a version of ProFTPd which seems
to be vulnerable to a buffer overflow when a user downloads
a malformed ASCII file.

An attacker with upload privileges on this host may abuse this
flaw to gain a root shell on this host.

*** The author of ProFTPD did not increase the version number
*** of his product when fixing this issue, so it might be false
*** positive.

Solution : Upgrade to ProFTPD 1.2.9 when available or to 1.2.8p
Risk factor : High";
		 
	
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the remote ProFTPD version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
		  
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

#
# The script code starts here : 
#

port = get_kb_item("Services/ftp");
if( ! port ) port = 21;

banner = get_ftp_banner(port:port);
if(!banner)exit(0);


if(egrep(pattern:"^220 ProFTPD 1\.([01]\..*|2\.[0-6][^0-9]|2\.[7-8][^0-9]|2\.9rc[0-2])", string:banner))
	security_hole(port);
