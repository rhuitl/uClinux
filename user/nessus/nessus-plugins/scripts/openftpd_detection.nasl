#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(14179);
 script_cve_id("CVE-2004-2523");
 script_bugtraq_id(10830);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"8261");
 }
 script_version("$Revision: 1.3 $");

 name["english"] = "OpenFTPD Detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running OpenFTPD - an FTP server designed to
help file sharing (aka 'warez').

Some version of this server are vulnerable to a remote format string
attack which may allow an attacker to execute arbitrary code on the remote
host.

*** Nessus did not actually check for this flaw, so this might be a false
*** positive

See also : http://archives.neohapsis.com/archives/bugtraq/2004-07/0350.html
Solution : Disable the remote service
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of OpenFTPD";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "General";
 script_family(english:family["english"]);
 
 script_dependencies("find_service2.nasl");
 script_require_ports(21, "Services/ftp");
 exit(0);
}



include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);
#
# We only check for the banner :
# - Most (all) OpenFTPD server do not accept anonymous connections
# - The use of OpenFTPD is not encouraged in a corporation environment
#
if ( egrep(pattern:"^220 OpenFTPD server", string:banner ) )
	security_hole(port);
