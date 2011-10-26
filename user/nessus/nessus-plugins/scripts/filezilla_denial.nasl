#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(17593);
 script_cve_id("CVE-2005-0850", "CVE-2005-0851");
 script_bugtraq_id(12865);
 script_version("$Revision: 1.5 $");

 name["english"] = "FileZilla FTP Server Denial of Service Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running FileZilla - an FTP server.

There is a flaw in the remote version of this software which may 
allow an authenticated attacker to crash the remote host by requesting
DOS devices (CON, NUL, etc...) or by misusing the zlib compression
mode.

Solution : Upgrade to version 0.9.6 of this service
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of FileZilla";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 
 script_dependencies("ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220.*FileZilla Server version 0\.([0-8]\.|9\.[0-5][^0-9])", string:banner))
        security_hole(port);

