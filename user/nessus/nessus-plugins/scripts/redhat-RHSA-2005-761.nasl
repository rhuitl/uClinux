#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19675);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2491");

 name["english"] = "RHSA-2005-761: pcre";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated pcre packages are now available to correct a security issue.

  This update has been rated as having moderate security impact by the
  Red Hat Security Response Team

  PCRE is a Perl-compatible regular expression library.

  An integer overflow flaw was found in PCRE, triggered by a maliciously
  crafted regular expression. On systems that accept arbitrary regular
  expressions from untrusted users, this could be exploited to execute
  arbitrary code with the privileges of the application using the library.
  The Common Vulnerabilities and Exposures project assigned the name
  CVE-2005-2491 to this issue.

  The security impact of this issue varies depending on the way that
  applications make use of PCRE. For example, the Apache web server uses the
  system PCRE library in order to parse regular expressions, but this flaw
  would only allow a user who already has the ability to write .htaccess
  files to gain \'apache\' privileges. For applications supplied with Red Hat
  Enterprise Linux, a maximum security impact of moderate has been assigned.

  Users should update to these erratum packages that contain a backported
  patch to correct this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-761.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pcre packages";
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
if ( rpm_check( reference:"pcre-3.4-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-3.4-2.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-3.9-10.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-3.9-10.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-4.5-3.2.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"pcre-devel-4.5-3.2.RHEL4", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pcre-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
if ( rpm_exists(rpm:"pcre-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}
if ( rpm_exists(rpm:"pcre-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2491", value:TRUE);
}

set_kb_item(name:"RHSA-2005-761", value:TRUE);
