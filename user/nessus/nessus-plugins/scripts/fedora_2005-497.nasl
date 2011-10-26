#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18593);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-1704");
 
 name["english"] = "Fedora Core 3 2005-497: binutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-497 (binutils).

Binutils is a collection of binary utilities, including ar (for
creating, modifying and extracting from archives), as (a family of GNU
assemblers), gprof (for displaying call graph profile data), ld (the
GNU linker), nm (for listing symbols from object files), objcopy (for
copying and translating object files), objdump (for displaying
information from object files), ranlib (for generating an index for
the contents of an archive), size (for listing the section sizes of an
object or archive file), strings (for listing printable strings from
files), strip (for discarding symbols), and addr2line (for converting
addresses to file and line).

* Wed Jun 29 2005 Jakub Jelinek 2.15.92.0.2-5.1

- bfd and readelf robustification (CVE-2005-1704, #158680)
- fix buffer overflows in readelf (#149506)



Solution : http://www.fedoranews.org/blog/index.php?p=735
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the binutils package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"binutils-2.15.92.0.2-5.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"binutils-debuginfo-2.15.92.0.2-5.1", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"binutils-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-1704", value:TRUE);
}
