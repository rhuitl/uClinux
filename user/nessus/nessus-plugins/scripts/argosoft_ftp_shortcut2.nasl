#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16334);
 script_cve_id("CVE-2005-0519");
 script_bugtraq_id(12487, 12632);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "ArGoSoft FTP Server Shortcut File Extension Filter Bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ArGoSoft FTP Server. 

It is reported that ArGoSoft FTP Server is prone to a vulnerability that 
allows a user to bypass a filter forbidding link upload. An attacker, 
exploiting this flaw, may be able to have read and write access to any 
files and directories on the FTP server.

Solution : Upgrade to ArGoSoft FTP 1.4.2.8 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the version of the remote ArGoSoft server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220 ArGoSoft FTP Server.*Version.*\(1\.([0-3]\.*|4\.[0-1]\.|4\.2.\.[0-7][^0-9])", string:banner) ) security_hole(port);
