#
# This script was written by Tenable Network Security
#

if(description)
{
 script_id(16270);
 script_cve_id("CVE-2005-0312");
 script_bugtraq_id(12384);
 script_version("$Revision: 1.3 $");
	
 name["english"] = "War FTP Daemon Remote Denial Of Service Vulnerability";
 script_name(english:name["english"]);
 desc["english"] = "
The remote host is running War FTP Daemon, an FTP server for Windows.

The remote version of this software is prone to a remote denial of
service vulnerability.  An attacker may exploit this flaw to crash the
remote service. 

Solution : Upgrade to War FTP Daemon 1.82-RC10.
Risk factor : High";

 script_description(english:desc["english"]);
 summary["english"] = "Checks the version of War FTP";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security.");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencies("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


include("ftp_func.inc");

port = get_kb_item("Services/ftp");

if(!port)port = 21;

if(get_port_state(port))
{
 r = get_ftp_banner(port:port);
 if(!r)exit(0);

 if(egrep(pattern:"WarFTPd 1\.([0-9]\.|[0-7][0-9]\.|8[0-1]\.|82\.00-RC[0-9][^0-9]).*Ready",string:r))
 {
  security_hole(port);
 }
}
