#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15977);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1158");
 
 name["english"] = "Fedora Core 2 2004-548: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-548 (kdelibs).

Libraries for the K Desktop Environment:
KDE Libraries included: kdecore (KDE core library), kdeui (user
interface),
kfm (file manager), khtmlw (HTML widget), kio (Input/Output,
networking),
kspell (spelling checker), jscript (javascript), kab (addressbook),
kimgio (image manipulation).


* Tue Dec 14 2004 Than Ngo
6:3.2.2-10.FC2

- apply the patch to fix Konqueror Window Injection Vulnerability
#142510
CVE-2004-1158, Thanks to KDE security team
- Security Advisory: plain text password exposure, #142487
thanks to KDE security team

* Tue Sep 07 2004 Than Ngo
6:3.2.2-9.FC2

- add patch to fix KDE trash always full #122988



Solution : http://www.fedoranews.org/blog/index.php?p=198
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs-3.2.2-10.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.2.2-10.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-debuginfo-3.2.2-10.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdelibs-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-1158", value:TRUE);
}
