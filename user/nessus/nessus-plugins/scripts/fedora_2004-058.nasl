#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13671);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2003-1023");
 
 name["english"] = "Fedora Core 1 2004-058: mc";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2004-058 (mc).

Midnight Commander is a visual shell much like a file manager, only
with many more features. It is a text mode application, but it also
includes mouse support if you are running GPM. Midnight Commander's
best features are its ability to FTP, view tar and zip files, and to
poke into RPMs for specific files.

* Sat Jan 31 2004 Jakub Jelinek <jakub redhat com> 4.6.0-8.4

- fix previous patch

* Fri Jan 30 2004 Jakub Jelinek <jakub redhat com> 4.6.0-8.3

- update php.syntax file (#112645)
- fix crash with large syntax file (#112644)

* Fri Jan 23 2004 Jakub Jelinek <jakub redhat com> 4.6.0-8.2

- update CVE-2003-1023 fix to still make vfs symlinks relative,
  but with bounds checking

* Sat Jan 17 2004 Warren Togami <wtogami redhat com> 4.6.0-8.1

- rebuild for FC1

* Sat Jan 17 2004 Warren Togami <wtogami redhat com> 4.6.0-7

- BuildRequires glib2-devel, slang-devel, XFree86-devel,
  e2fsprogs-devel, gettext
- Copyright -> License
- PreReq -> Requires
- Explicit zero epoch in versioned dev dep
- /usr/share/mc directory ownership
- Improve summary
- (Seth Vidal QA) fix for CVE-2003-1023 (Security)



Solution : http://www.fedoranews.org/updates/FEDORA-2004-058.shtml
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the mc package";
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
if ( rpm_check( reference:"mc-4.6.0-8.4", prefix:"mc-", release:"FC1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"mc-", release:"FC1") )
{
 set_kb_item(name:"CVE-2003-1023", value:TRUE);
}
