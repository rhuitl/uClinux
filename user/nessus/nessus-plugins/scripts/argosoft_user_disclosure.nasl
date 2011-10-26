#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(16094);
 script_cve_id("CVE-2004-1428");
 script_bugtraq_id(12139);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "ArGoSoft FTP Server User Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the ArGoSoft FTP Server. 

The remote version of this software returns different error messages when
a user attempts to log in using a non-existant username or a bad password.

An attacker may exploit this flaw to set up a dictionary attack against the
remote host in order to obtain a list of valid user names.

Solution : Upgrade to ArGoSoft FTP 1.4.2.2 or newer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the error message of the remote FTP server";
 
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

include('global_settings.inc');
include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = ftp_recv_line(socket:soc);
if ("ArGoSoft" >!< banner ) exit(0);
send(socket:soc, data:'USER nessus' + rand() + rand() + rand() + '\r\n');
r = ftp_recv_line(socket:soc);
if ( egrep(string:r, pattern:"^530 User .* does not exist", icase:TRUE) )
	security_note(port);
ftp_close(socket:soc);
