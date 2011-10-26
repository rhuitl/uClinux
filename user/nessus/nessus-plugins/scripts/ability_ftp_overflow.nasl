#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(15628);
 script_cve_id("CVE-2004-1626", "CVE-2004-1627");
 script_bugtraq_id(11508);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"11030");
 }
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Ability FTP Server Remote Buffer Overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Ability FTP Server. It is reported that 
the remote version of this software is prone to a remote buffer overflow 
via the STOR command. An attacker, exploiting this flaw, would only need to 
be able to craft and send a query to the FTP server on its service port 
(usually 21).

Solution : Upgrade to Ability FTP Server 2.35 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Gets the version of the remote Ability FTP server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
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

if ( egrep(pattern:"^220 Welcome to Code-Crafters - Ability Server ([0-1]\.*|2\.([0-2]|3[0-4]))[^0-9]", string:banner) ) security_hole(port);



