#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15412);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0755");

 name["english"] = "RHSA-2004-441: irb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated ruby package that fixes insecure file permissions for CGI
  session
  files is now available.

  Ruby is an interpreted scripting language for object-oriented programming.

  Andres Salomon reported an insecure file permissions flaw in the CGI
  session management of Ruby. FileStore created world readable files that
  could allow a malicious local user the ability to read CGI session data.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2004-0755 to this issue.

  Users are advised to upgrade to this erratum package, which contains a
  backported patch to CGI::Session FileStore.




Solution : http://rhn.redhat.com/errata/RHSA-2004-441.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the irb packages";
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
if ( rpm_check( reference:"irb-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.4-2.AS21.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"irb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0755", value:TRUE);
}

set_kb_item(name:"RHSA-2004-441", value:TRUE);
