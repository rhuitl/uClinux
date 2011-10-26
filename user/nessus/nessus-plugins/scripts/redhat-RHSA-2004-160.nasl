#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12487);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2004-0179");

 name["english"] = "RHSA-2004-160: openoffice.org";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated OpenOffice packages that fix a vulnerability in neon exploitable by
  a malicious DAV server are now available.

  OpenOffice.org is an Open Source, community-developed, multi-platform
  office productivity suite. OpenOffice internally uses inbuilt code
  from neon, an HTTP and WebDAV client library.

  Versions of the neon client library up to and including 0.24.4 have been
  found to contain a number of format string bugs. An attacker could create
  a malicious WebDAV server in such a way as to allow arbitrary code
  execution on the client should a user connect to it using OpenOffice. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CVE-2004-0179 to this issue.

  Users of OpenOffice are advised to upgrade to these updated packages, which
  contain a patch correcting this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-160.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openoffice.org packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openoffice.org-1.1.0-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-i18n-1.1.0-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openoffice.org-libs-1.1.0-15.EL", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openoffice.org-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0179", value:TRUE);
}

set_kb_item(name:"RHSA-2004-160", value:TRUE);
