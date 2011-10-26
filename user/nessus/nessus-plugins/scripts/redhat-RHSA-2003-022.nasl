#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12354);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-1146");

 name["english"] = "RHSA-2003-022: glibc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated glibc packages are available to fix a buffer overflow in the
  resolver.

  The GNU C library package, glibc, contains standard libraries used by
  multiple programs on the system.

  A read buffer overflow vulnerability exists in the glibc resolver code in
  versions of glibc up to and including 2.2.5. The vulnerability is triggered
  by DNS packets larger than 1024 bytes and can cause applications to crash.

  In addition to this, several non-security related bugs have been fixed,
  the majority for the Itanium (IA64) platform.

  All Red Hat Linux Advanced Server users are advised to upgrade to these
  errata packages which contain a patch to correct this vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2003-022.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the glibc packages";
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
if ( rpm_check( reference:"glibc-2.2.4-31.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-common-2.2.4-31.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-devel-2.2.4-31.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"glibc-profile-2.2.4-31.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"nscd-2.2.4-31.7", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"glibc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1146", value:TRUE);
}

set_kb_item(name:"RHSA-2003-022", value:TRUE);
