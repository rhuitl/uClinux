#
# This script was written by Audun Larsen <larsen@xqus.com>
#

if(description)
{
 script_id(12075);
 script_cve_id("CVE-2004-0325");
 script_bugtraq_id(9702);
 script_version("$Revision: 1.7 $");
 name["english"] = "TYPSoft FTP 1.10";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be running TYPSoft FTP 1.10 or earlier.

TYPESoft FTP Server is prone to a remote denial of service vulnerability
that may allow an attacker to cause the server to crash.

Solution : Use a different FTP server.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of TYPSoft FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
   banner = get_ftp_banner(port:port);
   if ( ! banner ) exit(0);
   if(egrep(pattern:".*TYPSoft FTP Server (0\.|1\.[0-9][^0-9]|1\.10[^0-9])", string:banner) )
    security_warning(port);
}
