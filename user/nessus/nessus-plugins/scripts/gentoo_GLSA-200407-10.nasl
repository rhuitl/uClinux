# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14543);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200407-10");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200407-10
(rsync: Directory traversal in rsync daemon)


    When rsyncd is used without chroot ("use chroot = false" in the rsyncd.conf
    file), the paths sent by the client are not checked thoroughly enough. If
    rsyncd is used with read-write permissions ("read only = false"), this
    vulnerability can be used to write files anywhere with the rights of the
    rsyncd daemon. With default Gentoo installations, rsyncd runs in a chroot,
    without write permissions and with the rights of the "nobody" user.
  
Impact

    On affected configurations and if the rsync daemon runs under a privileged
    user, a remote client can exploit this vulnerability to completely
    compromise the host.
  
Workaround

    You should never set the rsync daemon to run with "use chroot = false". If
    for some reason you have to run rsyncd without a chroot, then you should
    not set "read only = false".
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0426


Solution: 
    All users should update to the latest version of the rsync package.
    # emerge sync
    # emerge -pv ">=net-misc/rsync-2.6.0-r2"
    # emerge ">=net-misc/rsync-2.6.0-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200407-10] rsync: Directory traversal in rsync daemon");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Directory traversal in rsync daemon');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.0-r2"), vulnerable: make_list("le 2.6.0-r1")
)) { security_warning(0); exit(0); }
