# This script was automatically generated from the SSA-2003-141-06a
# Slackware Security Advisory
# It is released under the Nessus Script Licence.
# Slackware Security Advisories are copyright 1999-2004 Slackware Linux, Inc.
# SSA2nasl Convertor is copyright 2004 Michel Arboi
# See http://www.slackware.com/about/ or http://www.slackware.com/security/
# Slackware(R) is a registered trademark of Slackware Linux, Inc.

if (! defined_func("bn_random")) exit(0);
desc='
NOTE:  The original advisory quotes a section of the Slackware ChangeLog
which had inadvertently reversed the options to quotacheck.  The correct
option to use is \'m\'.  A corrected advisory follows:


An upgraded sysvinit package is available which fixes a problem with
the use of quotacheck in /etc/rc.d/rc.M.  The original version of
rc.M calls quotacheck like this:

    echo "Checking filesystem quotas:  /sbin/quotacheck -avugM"
    /sbin/quotacheck -avugM

The \'M\' option is wrong.  This causes the filesystem to be remounted,
and in the process any mount flags such as nosuid, nodev, noexec,
and the like, will be reset.  The correct option to use here is \'m\',
which does not attempt to remount the partition:

    echo "Checking filesystem quotas:  /sbin/quotacheck -avugm"
    /sbin/quotacheck -avugm

We recommend sites using file system quotas upgrade to this new package,
or edit /etc/rc.d/rc.M accordingly.


';
if (description) {
script_id(18723);
script_version("$Revision: 1.2 $");
script_category(ACT_GATHER_INFO);
script_family(english: "Slackware Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_copyright("This script is Copyright (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_require_keys("Host/Slackware/release", "Host/Slackware/packages");
script_description(english: desc);

script_xref(name: "SSA", value: "2003-141-06a");
script_summary("SSA-2003-141-06a REVISED quotacheck security fix in rc.M ");
name["english"] = "SSA-2003-141-06a REVISED quotacheck security fix in rc.M ";
script_name(english:name["english"]);
exit(0);
}

include('slackware.inc');
include('global_settings.inc');

if (slackware_check(osver: "9.0", pkgname: "sysvinit", pkgver: "2.84", pkgnum:  "26", pkgarch: "i386")) {
w++;
if (report_verbosity > 0) desc = strcat(desc, '
The package sysvinit is vulnerable in Slackware 9.0
Upgrade to sysvinit-2.84-i386-26 or newer.
');
}

if (w) { security_hole(port: 0, data: desc); }
