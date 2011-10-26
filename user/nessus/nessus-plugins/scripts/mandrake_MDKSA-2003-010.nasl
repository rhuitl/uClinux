#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:010
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13995);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0034", "CVE-2003-0035", "CVE-2003-0036");
 
 name["english"] = "MDKSA-2003:010: printer-drivers";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:010 (printer-drivers).


Karol Wiesek and iDefense disovered three vulnerabilities in the printer-drivers
package and tools it installs. These vulnerabilities allow a local attacker to
empty or create any file on the filesystem.
The first vulnerability is in the mtink binary, which has a buffer overflow in
its handling of the HOME environment variable.
The second vulnerability is in the escputil binary, which has a buffer overflow
in the parsing of the --printer-name command line argument. This is only
possible when esputil is suid or sgid; in Mandrake Linux 9.0 it was sgid 'sys'.
Successful exploitation will provide the attacker with the privilege of the
group 'sys'.
The third vulnerability is in the ml85p binary which contains a race condition
in the opening of a temporary file. By default this file is installed suid root
so it can be used to gain root privilege. The only caveat is that this file is
not executable by other, only by root or group 'sys'. Using either of the two
previous vulnerabilities, an attacker can exploit one of them to obtain 'sys'
privilege' and then use that to exploit this vulnerability to gain root
privilege.
MandrakeSoft encourages all users to upgrade immediately.
Aside from the security vulnerabilities, a number of bugfixes are included in
this update, for Mandrake Linux 9.0 users. GIMP-Print 4.2.5pre1, HPIJS 1.3,
pnm2ppa 1.12, mtink 0.9.53, and a new foomatic snapshot are included. For a list
of the many bugfixes, please refer to the RPM changelog.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:010
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the printer-drivers package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ghostscript-5.50-67.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-5.50-67.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-utils-5.50-67.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-drivers-1.1-15.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-1.1-0.20010923.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-6.51-24.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-6.51-24.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-4.1.99-16.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-devel-4.1.99-16.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"omni-0.4-11.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-1.0-15.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-1.0-15.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-1.0-15.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-drivers-1.1-48.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-1.1-0.20020323mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-6.53-13.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-6.53-13.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gimpprint-4.2.1-0.pre5.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-4.2.1-0.pre5.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-devel-4.2.1-0.pre5.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"omni-0.6.0-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-1.0-48.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-1.0-48.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-1.0-48.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"cups-drivers-1.1-84.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"foomatic-2.0.2-20021220.2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-7.05-33.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ghostscript-module-X-7.05-33.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"gimpprint-4.2.5-0.2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-4.2.5-0.2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libgimpprint1-devel-4.2.5-0.2.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libijs0-0.34-24.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libijs0-devel-0.34-24.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"omni-0.7.1-11.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-filters-1.0-84.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-testpages-1.0-84.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"printer-utils-1.0-84.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"printer-drivers-", release:"MDK8.0")
 || rpm_exists(rpm:"printer-drivers-", release:"MDK8.1")
 || rpm_exists(rpm:"printer-drivers-", release:"MDK8.2")
 || rpm_exists(rpm:"printer-drivers-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0034", value:TRUE);
 set_kb_item(name:"CVE-2003-0035", value:TRUE);
 set_kb_item(name:"CVE-2003-0036", value:TRUE);
}
