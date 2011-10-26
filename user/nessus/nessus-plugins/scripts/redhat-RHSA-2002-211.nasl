#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12325);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0838");

 name["english"] = "RHSA-2002-211: ggv";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated packages for gv, ggv, and kdegraphics fix a local buffer overflow
  when reading malformed PDF or PostScript files.

  [Updated 07 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Gv and ggv are user interfaces for the Ghostscript PostScript(R)
  interpreter used to display PostScript and PDF documents on an X Window
  System. KGhostview is the PostScript viewer for the K Desktop Environment.

  Zen Parse found a local buffer overflow in gv version 3.5.8 and earlier.
  An attacker can create a carefully crafted malformed PDF or PostScript file
  in such a way that when that file is viewed arbitrary commands can be
  executed.

  ggv and kghostview contain code derived from gv and therefore have the same
  vulnerability.

  All users of gv, ggv, and kghostview are advised to upgrade to the errata
  packages which contain patches to correct the vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2002-211.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the ggv packages";
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
if ( rpm_check( reference:"ggv-1.0.2-5.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-18.7x", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-2.2.2-2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-2.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"ggv-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-0838", value:TRUE);
}

set_kb_item(name:"RHSA-2002-211", value:TRUE);
