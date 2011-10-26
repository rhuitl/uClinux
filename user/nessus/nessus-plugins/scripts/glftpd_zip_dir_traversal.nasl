#
# (C) Tenable Network Security
# 

if (description)
{
 script_id(17245);
 script_cve_id("CVE-2005-0483");
 script_bugtraq_id(12586);
 script_version("$Revision: 1.3 $");
 name["english"] = "glFTPD ZIP Plugins Multiple Directory Traversal Vulnerabilities";
 script_name(english: name["english"]);

 desc["english"] = "
The remote glFTPD server is vulnerable to various directory traversal 
vulnerabilities when handling .ZIP files.

The plugins 'sitenfo.sh', 'sitezipchk.sh' and 'siteziplist.sh' are vulnerable
to a directory traversal vulnerability which may allow an attacker to force
the remote server to disclose arbitrary files by sending a specially
crafted request to the remote host.

Solution : Upgrade to glFTPd 2.0.0 RC8 or newer
Risk factor : High";

 script_description(english: desc["english"]);
 script_summary(english: "Checks the banner of the remote glFTPD server");

 script_category(ACT_GATHER_INFO);
 script_family(english: "FTP");

 script_copyright(english: "Copyright (C) 2005 Tenable Network Security");
 script_dependencie("find_service.nes", "ftp_anonymous.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}


#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21;
if (!get_port_state(port)) exit(0);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);

if ( egrep(pattern:"^220.* glftpd )(1\.|2\.00_RC[1-7] )", string:banner) )
	security_hole(port);

