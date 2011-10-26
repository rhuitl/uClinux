# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-06.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14457);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200403-06");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-06
(Multiple remote buffer overflow vulnerabilities in Courier)


    The vulnerabilities have been found in the \'SHIFT_JIS\' converter in
    \'shiftjis.c\' and \'ISO2022JP\' converter in \'so2022jp.c\'. An attacker may
    supply Unicode characters that exceed BMP (Basic Multilingual Plane) range,
    causing an overflow.
  
Impact

    An attacker without privileges may exploit this vulnerability remotely, allowing arbitrary code to be executed in order to gain unauthorized access.
  
Workaround

    While a workaround is not currently known for this issue, all users are
    advised to upgrade to the latest version of the affected packages.
  
References:
    http://www.securityfocus.com/bid/9845
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0224


Solution: 
    All users should upgrade to current versions of the affected packages:
    # emerge sync
    # emerge -pv ">=net-mail/courier-imap-3.0.0"
    # emerge ">=net-mail/courier-imap-3.0.0"
    # ** Or; depending on your installation... **
    # emerge -pv ">=net-mail/courier-0.45"
    # emerge ">=net-mail/courier-0.45"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-06] Multiple remote buffer overflow vulnerabilities in Courier");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple remote buffer overflow vulnerabilities in Courier');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/courier", unaffected: make_list("ge 0.45"), vulnerable: make_list("lt 0.45")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-mail/courier-imap", unaffected: make_list("ge 3.0.0"), vulnerable: make_list("lt 3.0.0")
)) { security_warning(0); exit(0); }
