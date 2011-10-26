# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-32.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14809);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200409-32");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-32
(getmail: Filesystem overwrite vulnerability)


    David Watson discovered a vulnerability in getmail when it is configured to
    run as root and deliver mail to the maildirs/mbox files of untrusted local
    users. A malicious local user can then exploit a race condition, or a
    similar symlink attack, and potentially cause getmail to create or
    overwrite files in any directory on the system.
  
Impact

    An untrusted local user could potentially create or overwrite files in any
    directory on the system. This vulnerability may also be exploited to have
    arbitrary commands executed as root.
  
Workaround

    Do not run getmail as a privileged user; or, in version 4, use an external
    MDA with explicitly configured user and group privileges.
  
References:
    http://www.qcc.ca/~charlesc/software/getmail-4/CHANGELOG
    http://article.gmane.org/gmane.mail.getmail.user/1430


Solution: 
    All getmail users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-mail/getmail-4.2.0"
    # emerge ">=net-mail/getmail-4.2.0"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-32] getmail: Filesystem overwrite vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'getmail: Filesystem overwrite vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/getmail", unaffected: make_list("ge 4.2.0"), vulnerable: make_list("lt 4.2.0")
)) { security_hole(0); exit(0); }
