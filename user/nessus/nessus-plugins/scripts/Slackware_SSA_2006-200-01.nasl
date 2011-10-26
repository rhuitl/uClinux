# This script was automatically generated from the SSA-2006-200-01
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
New Samba packages are available for Slackware 10.0, 10.1, 10.2,
and -current.

In Slackware 10.0, 10.1, and 10.2, Samba was evidently picking up
the libdm.so.0 library causing a Samba package issued primarily as
a security patch to suddenly require a library that would only be
present on the machine if the xfsprogs package (from the A series
but marked "optional") was installed.  Sorry -- this was not
intentional, though I do know that I\'m taking the chance of this
kind of issue when trying to get security related problems fixed
quickly (hopefully balanced with reasonable testing), and when the
fix is achieved by upgrading to a new version rather than with the
smallest patch possible to fix the known issue.  However, I tend
to trust that by following upstream sources as much as possible
I\'m also fixing some problems that aren\'t yet public.

So, all of the the 10.0, 10.1, and 10.2 packages have been rebuilt
on systems without the dm library, and should be able to directly
upgrade older samba packages without additional requirements.
Well, unless they are also under /patches.  ;-)

All the packages (including -current) have been patched with a
fix from Samba\'s CVS for some reported problems with winbind.
Thanks to Mikhail Kshevetskiy for pointing me to the patch.

I realize these packages don\'t really fix security issues, but
they do fix security patch packages that are less than a couple
of days old, so it seems prudent to notify slackware-security
(and any subscribed lists) again.  Sorry if it\'s noise...


';
if (description) {
script_id(22081);
script_version("$Revision: 1.1 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2006 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2006-200-01");
script_summary("SSA-2006-200-01 Samba 2.0.23 repackaged ");
name["english"] = "SSA-2006-200-01 Samba 2.0.23 repackaged ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "-current", pkgname: "samba", pkgver: "3.0.23", pkgnum:  "2", pkgarch: "i486")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package samba is vulnerable in Slackware -current
Upgrade to samba-3.0.23-i486-2 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
