#
# (C) Tenable Network Security
#

if (description)
{
	script_id(12067);
	script_cve_id("CVE-2004-2244", "CVE-2004-2345");
	script_bugtraq_id(9703, 9705);
	if (defined_func("script_xref")) {
	  script_xref(name:"OSVDB", value:"4011");
	}
 	script_version ("$Revision: 1.13 $");
	script_name(english: "Oracle SOAP denial");
	script_description(english:"
The remote Oracle Database, according to its version number, is vulnerable 
to a denial of service related to SOAP and XML.

An attacker may use these flaws to disable the remote database remotely.

Solution : Upgrade to Oracle 9.2.0.3 - http://metalink.oracle.com
See also : http://otn.oracle.com/deploy/security/pdf/2004alert65.pdf
Risk factor : High");

	script_summary(english: "Checks the version of the remote database");

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
    if(ereg(pattern:".*Version (9\.0\.[0-1]|9\.2\.0\.[0-2]).*", string:version))
	security_hole(port);
}
