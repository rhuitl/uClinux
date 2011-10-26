# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-01.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16392);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200501-01");
 script_cve_id("CVE-2004-1282");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200501-01
(LinPopUp: Buffer overflow in message reply)


    Stephen Dranger discovered that LinPopUp contains a buffer
    overflow in string.c, triggered when replying to a remote user message.
  
Impact

    A remote attacker could craft a malicious message that, when
    replied using LinPopUp, would exploit the buffer overflow. This would
    result in the execution of arbitrary code with the privileges of the
    user running LinPopUp.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1282
    http://tigger.uic.edu/~jlongs2/holes/linpopup.txt


Solution: 
    All LinPopUp users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/linpopup-2.0.4-r1"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200501-01] LinPopUp: Buffer overflow in message reply");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LinPopUp: Buffer overflow in message reply');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/linpopup", unaffected: make_list("ge 2.0.4-r1"), vulnerable: make_list("lt 2.0.4-r1")
)) { security_warning(0); exit(0); }
