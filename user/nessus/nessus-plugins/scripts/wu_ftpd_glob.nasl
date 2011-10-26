#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# 
#
# See the Nessus Scripts License for details
#
# Ref:  http://www.suse.de/de/security/2001_043_wuftpd_txt.html


if(description)
{
 script_id(11332);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2001-0935");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-A-0009");
 
 name["english"] = "wu-ftpd glob vulnerability (2)";
 
 script_name(english:name["english"],
 	     francais:name["francais"]);
	     
 desc["english"] = "
The remote FTP server, according to its version number,
was found vulnerable to security related bugs uncovered by
the SuSE security team.

Solution : upgrade to 2.6.1 or newer
Risk factor : Medium";

		 
		
	 	     
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the remote FTPd version");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
 		  francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
		  
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


banner = get_ftp_banner(port: port);
if(banner)
{
 if(egrep(pattern:".*wu-(1\..*|2\.[0-5]\.|2\.6\.0).*", string:banner))security_warning(port);
}
