#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20871);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CVE-2005-4667");
 
 name["english"] = "Fedora Core 4 2006-098: unzip";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2006-098 (unzip).

The unzip utility is used to list, test, or extract files from a zip
archive.  Zip archives are commonly found on MS-DOS systems.  The zip
utility, included in the zip package, creates zip archives.  Zip and
unzip are both compatible with archives created by PKWARE(R)'s PKZIP
for MS-DOS, but the programs' options and default behaviors do differ
in some respects.

Install the unzip package if you need to list, test or extract files from
a zip archive.


* Mon Feb  6 2006 Ivana Varekova <varekova redhat com> 5.51-13.fc4
- fix bug 178961 - CVE-2005-4667 - unzip long file name buffer overflow
* Wed Aug  3 2005 Ivana Varekova <varekova redhat com> 5.51-12.fc4
- fix bug 164928 - TOCTOU issue in unzip
* Mon May  9 2005 Ivana Varekova <varekova redhat com> 5.51-11
- fix bug 156959 Ã¢ÂÂ invalid file mode on created files



Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the unzip package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"unzip-5.51-13.fc4", release:"FC4") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"unzip-", release:"FC4") )
{
 set_kb_item(name:"CVE-2005-4667", value:TRUE);
}
