#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19488);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2471");

 name["english"] = "RHSA-2005-743: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated netpbm packages that fix a security issue are now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The netpbm package contains a library of functions that support
  programs for handling various graphics file formats, including .pbm
  (portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
  .ppm (portable pixmaps) and others.

  A bug was found in the way netpbm converts PostScript files into PBM, PGM
  or PPM files. An attacker could create a carefully crafted PostScript file
  in such a way that it could execute arbitrary commands when the
  file is processed by a victim using pstopnm. The Common Vulnerabilities
  and Exposures project assigned the name CVE-2005-2471 to this issue.

  All users of netpbm should upgrade to the updated packages, which
  contain a backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-743.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm packages";
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
if ( rpm_check( reference:"netpbm-9.24-9.AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-9.24-11.30.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-11.30.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-11.30.2", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-10.25-2.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-10.25-2.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-10.25-2.EL4.1", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"netpbm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2005-2471", value:TRUE);
}
if ( rpm_exists(rpm:"netpbm-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2005-2471", value:TRUE);
}
if ( rpm_exists(rpm:"netpbm-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2471", value:TRUE);
}

set_kb_item(name:"RHSA-2005-743", value:TRUE);
