# This script derived from aix_ftpd by Michael Scheidell at SECNAP
#
# original script  written by Renaud Deraison <deraison@cvs.nessus.org>
# 
# See the Nessus Scripts License for details
#
#
# Note by rd: 
# 	- Disabled the DoS code, as it will completely crash the
#	  remote host, something that should not be done from within
#	  a ACT_MIXED_ATTACK plugin.
#

if(description)
{
 script_id(11185);
 script_bugtraq_id(6297);
 script_version("$Revision: 1.7 $");
 name["english"] = "vxworks ftpd buffer overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
It might be possible to make the remote FTP server
crash by issuing this command :

	CEL aaaa(...)aaaa
	
This problem is similar to the 'aix ftpd' overflow
but on embedded vxworks based systems like the 3com
nbx IP phone call manager and seems to cause the server
to crash.

*** Note that Nessus solely relied on the banner of
*** the remote server to issue this warning. 

Solution: If you are using an embedded vxworks
product, please contact the OEM vendor and reference
WindRiver field patch TSR 296292. If this is the 
3com NBX IP Phone call manager, contact 3com.

This affects VxWorks ftpd versions 5.4 and 5.4.2

For more information, see CERT VU 317417
http://www.kb.cert.org/vuls/id/317417
or full security alert at
http://www.secnap.net/security/nbx001.html

Risk factor : High";
		 
 script_description(english:desc["english"]);
 
 script_summary(english:"Checks if the vxworks ftpd can be buffer overflowed");
 script_category(ACT_GATHER_INFO); 
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002 Michael Scheidell",
 		  francais:"Ce script est Copyright (C) 2002 Michael Scheidell");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port: port);

if(!banner)exit(0);
#VxWorks (5.4) FTP server ready
#220 VxWorks (5.4.2) FTP server ready
#above affected,
# below MIGHT be ok:
#220 VxWorks FTP server (VxWorks 5.4.2) ready
# and thus the banner check may be valid

# for some reason, escaping the parens causes a login failure here
#                             (5.4) or (5.4.[1-2])
 if(egrep(pattern:".*xWorks .(5\.4.|5\.4\.[1-2])[^0-9].*FTP",
   	 string:banner)){
  	 security_hole(port);
	 } 
