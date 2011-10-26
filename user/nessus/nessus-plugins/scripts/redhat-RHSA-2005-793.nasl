#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20058);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-2978");

 name["english"] = "RHSA-2005-793: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated netpbm packages that fix a security issue are now available.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The netpbm package contains a library of functions that support
  programs for handling various graphics file formats, including .pbm
  (portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
  .ppm (portable pixmaps) and others.

  A bug was found in the way netpbm converts Portable Anymap (PNM) files into
  Portable Network Graphics (PNG). The usage of uninitialised variables in
  the pnmtopng code allows an attacker to change stack contents when
  converting to PNG files with pnmtopng using the \'-trans\' option. This may
  allow an attacker to execute arbitrary code. The Common Vulnerabilities
  and Exposures project assigned the name CVE-2005-2978 to this issue.

  All users of netpbm should upgrade to the updated packages, which
  contain a backported patch to resolve this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2005-793.html
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
if ( rpm_check( reference:"netpbm-10.25-2.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-10.25-2.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-10.25-2.EL4.2", release:"RHEL4") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"netpbm-", release:"RHEL4") )
{
 set_kb_item(name:"CVE-2005-2978", value:TRUE);
}

set_kb_item(name:"RHSA-2005-793", value:TRUE);
