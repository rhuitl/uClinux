# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21347);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200605-05");
 script_cve_id("CVE-2006-2083");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200605-05
(rsync: Potential integer overflow)


    An integer overflow was found in the receive_xattr function from
    the extended attributes patch (xattr.c) for rsync. The vulnerable
    function is only present when the "acl" USE flag is set.
  
Impact

    A remote attacker with write access to an rsync module could craft
    malicious extended attributes which would trigger the integer overflow,
    potentially resulting in the execution of arbitrary code with the
    rights of the rsync daemon.
  
Workaround

    Do not provide write access to an rsync module to untrusted
    parties.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2083


Solution: 
    All rsync users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/rsync-2.6.8"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200605-05] rsync: Potential integer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'rsync: Potential integer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/rsync", unaffected: make_list("ge 2.6.8"), vulnerable: make_list("lt 2.6.8")
)) { security_hole(0); exit(0); }
