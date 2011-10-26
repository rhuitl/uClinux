#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17180);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0077");

 name["english"] = "RHSA-2005-072: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated perl-DBI package that fixes a temporary file flaw in
  DBI::ProxyServer is now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  DBI is a database access Application Programming Interface (API) for
  the Perl programming language.

  The Debian Security Audit Project discovered that the DBI library creates a
  temporary PID file in an insecure manner. A local user could overwrite or
  create files as a different user who happens to run an application which
  uses DBI::ProxyServer. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2005-0077 to this issue.

  Users should update to this erratum package which disables the temporary
  PID file unless configured.




Solution : http://rhn.redhat.com/errata/RHSA-2005-072.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"perl-DBI-1.40-8", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"perl-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-0077", value:TRUE);
}

set_kb_item(name:"RHSA-2005-072", value:TRUE);
