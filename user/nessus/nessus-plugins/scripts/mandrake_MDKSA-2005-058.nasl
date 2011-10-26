#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:058
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17346);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-0237", "CVE-2005-0365", "CVE-2005-0396");
 
 name["english"] = "MDKSA-2005:058: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:058 (kdelibs).



A vulnerability in dcopserver was discovered by Sebastian Krahmer of the SUSE
security team. A local user can lock up the dcopserver of other users on the
same machine by stalling the DCOP authentication process, causing a local
Denial of Service. dcopserver is the KDE Desktop Communication Procotol daemon
(CVE-2005-0396).

As well, the IDN (International Domain Names) support in Konqueror is
vulnerable to a phishing technique known as a Homograph attack. This attack is
made possible due to IDN allowing a website to use a wide range of
international characters that have a strong resemblance to other characters.
This can be used to trick users into thinking they are on a different trusted
site when they are in fact on a site mocked up to look legitimate using these
other characters, known as homographs. This can be used to trick users into
providing personal information to a site they think is trusted (CVE-2005-0237).

Finally, it was found that the dcopidlng script was vulnerable to symlink
attacks, potentially allowing a local user to overwrite arbitrary files of a
user when the script is run on behalf of that user. However, this script is
only used as part of the build process of KDE itself and may also be used by
the build processes of third- party KDE applications (CVE-2005-0365).

The updated packages are patched to deal with these issues and Mandrakesoft
encourages all users to upgrade immediately.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:058
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"kdelibs-common-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2-36.12.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-common-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libkdecore4-devel-3.2.3-104.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"kdelibs-", release:"MDK10.0")
 || rpm_exists(rpm:"kdelibs-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0237", value:TRUE);
 set_kb_item(name:"CVE-2005-0365", value:TRUE);
 set_kb_item(name:"CVE-2005-0396", value:TRUE);
}
