#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12456);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-1023");

 name["english"] = "RHSA-2004-035: gmc";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated mc packages that resolve a buffer overflow vulnerability are now
  available.

  Midnight Commander is a visual shell much like a file manager.

  A buffer overflow has been found in Midnight Commander\'s virtual filesystem
  code. Specifically, a stack-based buffer overflow in vfs_s_resolve_symlink
  of vfs/direntry.c allows remote attackers to execute arbitrary code during
  symlink conversion.

  Users of Midnight Commander should install these updated packages, which
  resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-035.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the gmc packages";
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
if ( rpm_check( reference:"gmc-4.5.51-36.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mc-4.5.51-36.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"mcserv-4.5.51-36.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"gmc-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-1023", value:TRUE);
}

set_kb_item(name:"RHSA-2004-035", value:TRUE);
