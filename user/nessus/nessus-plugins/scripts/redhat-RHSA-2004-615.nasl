#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15702);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0989");

 name["english"] = "RHSA-2004-615: libxml";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  An updated libxml2 package that fixes multiple buffer overflows is now
  available.

  libxml2 is a library for manipulating XML files.

  Multiple buffer overflow bugs have been found in libxml2 versions prior to
  2.6.14. If an attacker can trick a user into passing a specially crafted
  FTP URL or FTP proxy URL to an application that uses the vulnerable
  functions of libxml2, it could be possible to execute arbitrary code.
  Additionally, if an attacker can return a specially crafted DNS request to
  libxml2, it could be possible to execute arbitrary code. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CVE-2004-0989 to this issue.

  All users are advised to upgrade to this updated package, which contains
  backported patches and is not vulnerable to these issues.




Solution : http://rhn.redhat.com/errata/RHSA-2004-615.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the libxml packages";
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
if ( rpm_check( reference:"libxml2-2.4.19-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.4.19-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.4.19-6.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.5.10-7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.10-7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.10-7", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libxml-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0989", value:TRUE);
}
if ( rpm_exists(rpm:"libxml-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0989", value:TRUE);
}

set_kb_item(name:"RHSA-2004-615", value:TRUE);
