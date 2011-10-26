#
# (C) Renaud Deraison 
#

if (description)
{
	script_id(11563);
	script_bugtraq_id(7453);
 	script_version ("$Revision: 1.11 $");
	script_cve_id("CVE-2003-0222");
	script_name(english: "Oracle LINK overflow");
	script_description(english:"
The remote Oracle Database, according to its version number,
is vulnerable to a buffer overflow in the query CREATE DATABASE LINK.

An attacker with a database account may use this flaw to gain the control
on the whole database, or even to obtain a shell on this host.

Solution : See http://otn.oracle.com/deploy/security/pdf/2003alert54.pdf
Risk factor : High");

	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2003 Renaud Deraison");
	script_dependencie("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
	exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

version = get_kb_item(string("oracle_tnslsnr/",port,"/version"));
if (version)
{
  if(ereg(pattern:".*Version ([0-7]\.|8\.0\.[0-6]|8\.1\.[0-7]|9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_hole(port);
}
