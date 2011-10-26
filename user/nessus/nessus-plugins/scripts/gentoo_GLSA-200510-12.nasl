# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-12.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20032);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-12");
 script_cve_id("2005-2971");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-12
(KOffice, KWord: RTF import buffer overflow)


    Chris Evans discovered that the KWord RTF importer was vulnerable
    to a heap-based buffer overflow.
  
Impact

    An attacker could entice a user to open a specially-crafted RTF
    file, potentially resulting in the execution of arbitrary code with the
    rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2005-2971
    http://www.kde.org/info/security/advisory-20051011-1.txt


Solution: 
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-1.4.1-r1"
    All KWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/kword-1.4.1-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-12] KOffice, KWord: RTF import buffer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KOffice, KWord: RTF import buffer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/kword", unaffected: make_list("ge 1.4.1-r1"), vulnerable: make_list("lt 1.4.1-r1")
)) { security_warning(0); exit(0); }
