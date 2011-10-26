#
# (C) Tenable Network Security
#


if (description) {
  script_id(17654);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-0701");
  script_bugtraq_id(12749);

  name["english"] = "Oracle Database 8i/9i Multiple Directory Traversal Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote database server is affected by directory traversal flaws. 

Description :

According to its version number, the installation of Oracle on the
remote host is reportedly subject to multiple directory traversal
vulnerabilities that may allow a remote attacker to read, write, or
rename arbitrary files with the privileges of the Oracle Database
server.  An authenticated user can craft SQL queries such that they
would be able to retrieve any file on the system and potentially
retrieve and/or modify files in the same drive as the affected
application.

See also : 

http://www.argeniss.com/research/ARGENISS-ADV-030501.txt
http://lists.grok.org.uk/pipermail/full-disclosure/2005-March/032273.html
http://www.oracle.com/technology/deploy/security/pdf/cpu-jan-2005_advisory.pdf

Solution : 

Apply the January 2005 Critical Patch Update.

Risk Factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:R/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote directory traversal vulnerabilities in Oracle Database 8i/9i";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  family["english"] = "Databases";
  script_family(english:family["english"]);

  script_dependencies("oracle_tnslsnr_version.nasl");
  script_require_ports("Services/oracle_tnslsnr");

  exit(0);
}

include('global_settings.inc');
if ( report_paranoia < 1 ) exit(0);

port = get_kb_item("Services/oracle_tnslsnr");
if (isnull(port)) exit(0);


version = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (
  version &&
  ereg(pattern:".*Version (8\.(0\.([0-5]\.|6\.[0-3])|1\.([0-6]\.|7\.[0-4]))|9\.(0\.(0\.|1\.[0-5]|2\.[0-6]|3\.[0-1]|4\.[0-1])|2\.0\.[0-5])|10\.(0\.|1\.0\.[0-3]))", string:version)
) security_warning(port);
