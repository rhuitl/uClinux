# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-16.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18531);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200506-16");
 script_cve_id("CVE-2005-1111");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-16
(cpio: Directory traversal vulnerability)


    A vulnerability has been found in cpio that can potentially allow
    a cpio archive to extract its files to an arbitrary directory of the
    creator\'s choice.
  
Impact

    An attacker could create a malicious cpio archive which would
    create files in arbitrary locations on the victim\'s system. This issue
    could also be used in conjunction with a previous race condition
    vulnerability (CVE-2005-1111) to change permissions on files owned by
    the victim.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/396429
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1111


Solution: 
    All cpio users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-arch/cpio-2.6-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-16] cpio: Directory traversal vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cpio: Directory traversal vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-arch/cpio", unaffected: make_list("ge 2.6-r3"), vulnerable: make_list("lt 2.6-r3")
)) { security_warning(0); exit(0); }
