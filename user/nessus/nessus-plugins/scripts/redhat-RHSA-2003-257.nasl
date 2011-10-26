#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12415);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2003-0615", "CVE-2002-1323");

 name["english"] = "RHSA-2003-257: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated Perl packages that fix a security issue in Safe.pm and a cross-site
  scripting (XSS) vulnerability in CGI.pm are now available.

  Perl is a high-level programming language commonly used for system
  administration utilities and Web programming.

  Two security issues have been found in Perl that affect the Perl packages
  shipped with Red Hat Enterprise Linux:

  When safe.pm versions 2.0.7 and earlier are used with Perl 5.8.0 and
  earlier, it is possible for an attacker to break out of safe compartments
  within Safe::reval and Safe::rdo by using a redefined @_ variable. This is
  due to the fact that the redefined @_ variable is not reset between
  successive calls. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CVE-2002-1323 to this issue.

  A cross-site scripting vulnerability was discovered in the start_form()
  function of CGI.pm. The vulnerability allows a remote attacker to insert a
  Web script via a URL fed into the form\'s action parameter. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2003-0615 to this issue.

  Users of Perl are advised to upgrade to these erratum packages, which
  contain Perl 5.6.1 with backported security patches correcting these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2003-257.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl packages";
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
if ( rpm_check( reference:"perl-5.6.1-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CGI-2.752-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-CPAN-1.59_54-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-DB_File-1.75-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-NDBM_File-1.75-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.6.1-36.1.99ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"perl-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0615", value:TRUE);
 set_kb_item(name:"CVE-2002-1323", value:TRUE);
}

set_kb_item(name:"RHSA-2003-257", value:TRUE);
