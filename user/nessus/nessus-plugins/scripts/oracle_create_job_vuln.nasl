#
# (C) Tenable Network Security
#

if (description)
{
	script_id(14641);
	script_bugtraq_id(10871, 11091, 11100, 11099, 11120);
 	script_cve_id("CVE-2004-0637", "CVE-2004-0638");
 	if ( defined_func("script_xref") ) script_xref(name:"IAVA", value:"2004-A-0014");

 	script_version ("$Revision: 1.12 $");
	script_name(english: "Oracle DBS_SCHEDULER vulnerability");
	script_description(english:"
The remote Oracle Database, according to its version number,
is vulnerable to a remote command execution vulnerability which may allow
an attacker who can execute SQL statements with certain privileges to
execute arbitrary commands on the remote host.

Solution : http://www.oracle.com/technology/deploy/security/pdf/2004alert68.pdf
Risk Factor : High");

	script_summary(english: "Checks the version of the remote Database");

	script_category(ACT_GATHER_INFO);
	script_family(english: "Databases");
	script_copyright(english: "This script is (C) 2004-2006 Tenable Network Security");
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
  if (ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-3]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-2]))", string:version)) security_hole(port);
}

