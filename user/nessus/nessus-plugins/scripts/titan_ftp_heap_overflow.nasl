#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14591);
 script_cve_id("CVE-2004-1641");
 script_bugtraq_id(11069);
 script_version ("$Revision: 1.4 $");
 name["english"] = "Titan FTP Server CWD heap overflow";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote is running Titan FTP Server. All versions up to and including 3.21 
are reported vulnerable to a remote heap overflow in the CWD command processing.

An attacker may deny service to legitimate users or execute arbitrary code on 
the remote host.

Solution : Upgrade to Titan FTP 3.22 or newer.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Check Titan FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "FTP";
 family["francais"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (! get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);

if (egrep(pattern:"^220.*Titan FTP Server ([0-2]\.|3\.([0-9][^0-9]|[0-1][0-9]|2[0-1])[^0-9])", string:banner) ) 
	security_hole(port);
