# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22214);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200608-15");
 script_cve_id("CVE-2006-3083", "CVE-2006-3084");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200608-15
(MIT Kerberos 5: Multiple local privilege escalation vulnerabilities)


    Unchecked calls to setuid() in krshd and v4rcp, as well as unchecked
    calls to seteuid() in kftpd and in ksu, have been found in the MIT
    Kerberos 5 program suite and may lead to a local root privilege
    escalation.
  
Impact

    A local attacker could exploit this vulnerability to execute arbitrary
    code with elevated privileges.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3083
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3084


Solution: 
    All MIT Kerberos 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-crypt/mit-krb5-1.4.3-r3"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200608-15] MIT Kerberos 5: Multiple local privilege escalation vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MIT Kerberos 5: Multiple local privilege escalation vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-crypt/mit-krb5", unaffected: make_list("ge 1.4.3-r3"), vulnerable: make_list("lt 1.4.3-r3")
)) { security_hole(0); exit(0); }
