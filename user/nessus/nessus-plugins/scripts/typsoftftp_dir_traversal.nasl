#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: joetesta@hushmail.com and Kistler Ueli <iuk@gmx.ch>
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14706);
 script_bugtraq_id(2489);
 script_cve_id("CVE-2002-0558");
 script_version("$Revision: 1.4 $");
 name["english"] = "TYPSoft directory traversal flaw";

 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be running TYPSoft FTP earlier than 0.97.5

This version is prone to directory traversal attacks.
An attacker could send specially crafted URL to view arbitrary 
files on the system.

Solution : Use a different FTP server or upgrade to the newest version
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of TYPSoft FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "FTP";
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

banner = get_ftp_banner(port:port);
if( ! banner ) exit(0);
if(egrep(pattern:".*TYPSoft FTP Server (0\.8|0\.9[0-6][^0-9]|0\.97[^0-9]|0\.97\.[0-4][^0-9])", string:banner) )
    security_warning(port);
