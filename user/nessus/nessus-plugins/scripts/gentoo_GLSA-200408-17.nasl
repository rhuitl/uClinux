# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-17.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14573);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-17");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-17
(rsync: Potential information leakage)


    The paths sent by the rsync client are not checked thoroughly enough. It
    does not affect the normal send/receive filenames that specify what files
    should be transferred. It does affect certain option paths that cause
    auxilliary files to be read or written.
  
Impact

    When rsyncd is used without chroot ("use chroot = false" in the
    rsyncd.conf file), this vulnerability could allow the listing of arbitrary
    files outside module\'s path and allow file overwriting outside module\'s
    path on rsync server configurations that allows uploading. Both
    possibilities are exposed only when chroot option is disabled.
  
Workaround

    You should never set the rsync daemon to run with "use chroot =
    false".
  
References:
    http://samba.org/rsync/#security_aug04
    http://lists.samba.org/archive/rsync-announce/2004/000017.html


Solution: 
    All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv ">=net-misc/rsync-2.6.0-r3"
    # emerge ">=net-misc/rsync-2.6.0-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-17] rsync: Potential information leakage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Potential information leakage');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.0-r3"), vulnerable: make_list("le 2.6.0-r2")
)) { security_warning(0); exit(0); }
