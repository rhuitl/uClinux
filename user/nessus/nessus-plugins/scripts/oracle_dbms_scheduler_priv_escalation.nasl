#
# (C) Tenable Network Security
#


if (description) {
  script_id(18204);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-1496");
  script_bugtraq_id(13509);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"9857");

  name["english"] = "Oracle 10g DBMS_SCHEDULER Privilege Escalation Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote database server is affected by a privilege escalation
issue. 

Description :

The remote host is running a version of Oracle 10g that, according to
its version number, permits a user with CREATE job privileges to
switch the session_user to SYS, which could allow privilege
escalation. 

See also : 

http://www.nessus.org/u?94ef874d

Solution : 

Apply the 10.0.1.4 patch set for Oracle 10g.

Risk Factor : 

Low / CVSS Base Score : 1
(AV:R/AC:L/Au:R/C:N/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for DBMS_SCHEDULER privilege escalation vulnerability in Oracle 10g";
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


ver = get_kb_item(string("oracle_tnslsnr/", port, "/version"));
if (ver) {
  if (ver =~ ".*Version 10\.1\.0\.0\.([23][^0-9]?|3\.1)") {
    security_note(port);
    exit(0);
  }
}
