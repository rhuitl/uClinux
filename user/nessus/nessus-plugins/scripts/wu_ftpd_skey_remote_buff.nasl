#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
# Ref: Michal Zalewski & Michael Hendrickx
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14372);
 script_bugtraq_id(8893);
 script_cve_id("CVE-2004-0185");
 
 if ( defined_func("script_xref") ) 
 {
 	script_xref(name:"OSVDB", value:"2715");
 	script_xref(name:"RHSA", value:"RHSA-2004:096-09");
 	script_xref(name:"DSA", value:"DSA-457-1");
 }
 script_version ("$Revision: 1.4 $");

 
 name["english"] = "wu-ftpd S/KEY authentication overflow ";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote Wu-FTPd server seems to be vulnerable to a remote overflow.

This version contains a remote overflow if s/key support is enabled. 
The skey_challenge function fails to perform bounds checking on the 
name variable resulting in a buffer overflow. 
With a specially crafted request, an attacker can execute arbitrary 
code resulting in a loss of integrity and/or availability.

It appears that this vulnerability may be exploited prior to authentication.
It is reported that S/Key support is not enabled by default, 
though some operating system distributions which ship Wu-Ftpd may have it 
enabled.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive.


Solution : Upgrade to Wu-FTPd 2.6.3 when available or disable SKEY or apply the
patches available at http://www.wu-ftpd.org

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

port = get_kb_item("Services/ftp");
if(!port)
	port = 21;
if (! get_port_state(port)) 
	exit(0);

banner = get_ftp_banner(port: port);
if( banner == NULL ) 
	exit(0);

if(egrep(pattern:".*wu-(2\.(5\.|6\.[012])).*", string:banner))
	security_hole(port);
