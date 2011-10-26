#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15980);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1158");
 
 name["english"] = "Fedora Core 3 2004-551: kdebase";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-551 (kdebase).

Core applications for the K Desktop Environment. Included are: kdm
(replacement for xdm), kwin (window manager), konqueror (filemanager,
web browser, ftp client, ...), konsole (xterm replacement), kpanel
(application starter and desktop pager), kaudio (audio server),
kdehelp (viewer for kde help files, info and man pages), kthememgr
(system for managing alternate theme packages) plus other KDE
components (kcheckpass, kikbd, kscreensaver, kcontrol, kfind,
kfontmanager, kmenuedit).


* Tue Dec 14 2004 Than Ngo
6:3.3.1-4.3.FC3

- apply the patch to fix Konqueror Window Injection Vulnerability
#142510
CVE-2004-1158, Thanks to KDE security team

* Fri Dec 10 2004 Than Ngo
6:3.3.1-4.2.FC3

- Security Advisory: plain text password exposure, thanks to KDE
security team
- the existing icon is lost, add patch to fix this problem #140196
- add patch to fix kfind hang on search #137582
- rebuild against samba-3.0.9 #139894
- add CVS patch to fix konqueror crash by dragging some text over the
navigation panel
- fix rpm conflict
- apply patch number 86
- add patch to fix man page problem konqueror, thanks to Andy
Shevchenko



Solution : http://www.fedoranews.org/blog/index.php?p=201
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdebase package";
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
if ( rpm_check( reference:"kdebase-3.3.1-4.3.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.3.1-4.3.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdebase-debuginfo-3.3.1-4.3.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdebase-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1158", value:TRUE);
}
