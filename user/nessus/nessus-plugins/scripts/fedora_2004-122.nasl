#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13700);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0411");
 
 name["english"] = "Fedora Core 2 2004-122: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-122 (kdelibs).

Libraries for the K Desktop Environment:
KDE Libraries included: kdecore (KDE core library), kdeui (user interface),
kfm (file manager), khtmlw (HTML widget), kio (Input/Output, networking),
kspell (spelling checker), jscript (javascript), kab (addressbook),
kimgio (image manipulation).


Update Information:


iDEFENSE identified a vulnerability in the Opera Web Browser that could
allow remote attackers to create or truncate arbitrary files. The KDE team
has found that a similar vulnerability exists in KDE.


A flaw in the telnet URL handler can allow options to be passed to the
telnet program which can be used to allow file creation or overwriting.
An attacker could create a carefully crafted link such that when opened by
a victim it creates or overwrites a file in the victims home directory. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
the name CVE-2004-0411 to this issue.




Solution : http://www.fedoranews.org/updates/FEDORA-2004-122.shtml
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
if ( rpm_check( reference:"kdelibs-3.2.2-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.2.2-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-debuginfo-3.2.2-6", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdelibs-", release:"FC2") )
{
 set_kb_item(name:"CVE-2004-0411", value:TRUE);
}
