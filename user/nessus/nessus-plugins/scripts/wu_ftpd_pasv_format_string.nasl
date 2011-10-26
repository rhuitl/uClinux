#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#
# Affected: wu-ftpd up to 2.4.1

if(description)
{
 script_id(11331);
 script_bugtraq_id(2296);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2001-0187");
 
 name["english"] = "wu-ftpd PASV format string";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote WU-FTPd server, according to its version number,
is vulnerable to a format string attack when running in debug
mode.

Solution : upgrade it to the latest version
Risk factor : High";
		 
		 
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the remote ftpd version");
 script_category(ACT_GATHER_INFO); 
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
		  
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;

banner = get_ftp_banner(port:port);
if(banner)
{
  banner = tolower(banner);
  if(egrep(pattern:"wu-((1\..*)|2\.([0-3]\..*|4\.[0-1]))", string:banner))
  	security_hole(port);
}
