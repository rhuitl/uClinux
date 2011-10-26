#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12474);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2004-0110");

 name["english"] = "RHSA-2004-090: libxml";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated libxml2 packages that fix an overflow when parsing remote resources
  are now available.

  libxml2 is a library for manipulating XML files.

  Yuuichi Teranishi discovered a flaw in libxml2 versions prior to 2.6.6.
  When fetching a remote resource via FTP or HTTP, libxml2 uses special
  parsing routines. These routines can overflow a buffer if passed a very
  long URL. If an attacker is able to find an application using libxml2 that
  parses remote resources and allows them to influence the URL, then this
  flaw could be used to execute arbitrary code. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CVE-2004-0110
  to this issue.

  All users are advised to upgrade to these updated packages, which contain a
  backported fix and are not vulnerable to this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-090.html
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
if ( rpm_check( reference:"libxml2-2.4.19-5.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.4.19-5.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.4.19-5.ent", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-2.5.10-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-devel-2.5.10-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libxml2-python-2.5.10-6", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"libxml-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0110", value:TRUE);
}
if ( rpm_exists(rpm:"libxml-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0110", value:TRUE);
}

set_kb_item(name:"RHSA-2004-090", value:TRUE);
