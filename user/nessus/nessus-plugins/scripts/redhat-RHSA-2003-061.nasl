#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12367);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0146");

 name["english"] = "RHSA-2003-061: netpbm";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated NetPBM packages are available that fix a number of vulnerabilities
  in the netpbm libraries.

  The netpbm package contains a library of functions that support
  programs for handling various graphics file formats, including .pbm
  (portable bitmaps), .pgm (portable graymaps), .pnm (portable anymaps),
  .ppm (portable pixmaps), and others.

  During an audit of the NetPBM library, Al Viro, Alan Cox, and Sebastian
  Krahmer found a number of bugs that are potentially exploitable. These
  bugs could be exploited by creating a carefully crafted image in such a way
  that it executes arbitrary code when it is processed by either an
  application from the netpbm-progs package or an application that uses the
  vulnerable netpbm library.

  One way that an attacker could exploit these vulnerabilities would be to
  submit a carefully crafted image to be printed, as the LPRng print spooler
  used by default in Red Hat Linux Advanced Products releases uses netpbm
  utilities to parse various types of image files.

  Users are advised to upgrade to the updated packages, which contain patches
  that correct these vulnerabilities.




Solution : http://rhn.redhat.com/errata/RHSA-2003-061.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the netpbm packages";
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
if ( rpm_check( reference:"netpbm-9.24-9.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-devel-9.24-9.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"netpbm-progs-9.24-9.AS21.2", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"netpbm-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0146", value:TRUE);
}

set_kb_item(name:"RHSA-2003-061", value:TRUE);
