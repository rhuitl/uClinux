#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2006:007
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20901);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "SUSE-SA:2006:007: binutils,kdelibs3,kdegraphics3,koffice,dia,lyx";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2006:007 (binutils,kdelibs3,kdegraphics3,koffice,dia,lyx).


A SUSE specific patch to the GNU linker 'ld' removes redundant RPATH
and RUNPATH components when linking binaries.

Due to a bug in this routine ld occasionally left empty RPATH
components. When running a binary with empty RPATH components the
dynamic linker tries to load shared libraries from the current
directory.

By tricking users into running an affected application in a
directory that contains a specially crafted shared library an
attacker could execute arbitrary code with the user id of the
victim.


Solution : http://www.suse.de/security/advisories/2006_07_binutils.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the binutils,kdelibs3,kdegraphics3,koffice,dia,lyx package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"binutils-2.16.91.0.2-8.4", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3D-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-imaging-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-scan-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-tex-3.4.2-12.2", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.4.2-24.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.2-24.3", release:"SUSE10.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"binutils-2.15.90.0.1.1-32.13", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3.2.1-67.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3D-3.2.1-67.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-scan-3.2.1-67.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-tex-3.2.1-67.16", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.2.1-44.66", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.2.1-44.66", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"binutils-2.15.91.0.2-7.3", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"dia-0.92.2-128.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3D-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-imaging-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-scan-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-tex-3.3.0-13.7", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.3.0-34.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.3.0-34.12", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"binutils-2.15.94.0.2.2-3.3", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-3D-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-imaging-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-scan-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdegraphics3-tex-3.4.0-11.5", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-3.4.0-20.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs3-devel-3.4.0-20.11", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
