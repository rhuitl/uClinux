#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15704);
 script_cve_id("CVE-2004-2418");
 script_bugtraq_id(11645, 14339);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"11604");
 }
 script_version("$Revision: 1.5 $");
 
 name["english"] = "SlimFTPd Multiple Buffer Overflow Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be using SlimFTPd, a free, small,
standards-compliant FTP server for Windows. 

According to its banner, the version of SlimFTPd installed on the remote
host is prone to one or more buffer overflow vulnerabilities that can
lead to arbitrary code execution.  To exploit any of these flaws, an
attacker must first authenticate.

See also : http://archives.neohapsis.com/archives/fulldisclosure/2004-11/0293.html
           http://archives.neohapsis.com/archives/bugtraq/2005-07/0348.html
Solution : Upgrade to SlimFTPd version 3.17 or later.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for multiple buffer overflow vulnerabilities in SlimFTPd < 3.17";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


include("ftp_func.inc");


port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);


# There's a problem if...
if (
  # The version in the banner is <= 3.16 or...
  egrep(string:banner, pattern:"^220-SlimFTPd ([0-2]\.|3\.1[0-6][^0-9])")
) {
  security_hole(port);
}
