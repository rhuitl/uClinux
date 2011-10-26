# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-05.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15431);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200410-05");
 script_cve_id("CVE-2004-0884");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200410-05
(Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities)


    Cyrus-SASL contains a remote buffer overflow in the digestmda5.c file.
    Additionally, under certain conditions it is possible for a local user to
    exploit a vulnerability in the way the SASL_PATH environment variable is
    honored (CVE-2004-0884).
  
Impact

    An attacker might be able to execute arbitrary code with the Effective ID
    of the application calling the Cyrus-SASL libraries.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0884


Solution: 
    All Cyrus-SASL users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=dev-libs/cyrus-sasl-2.1.18-r2"
    # emerge ">=dev-libs/cyrus-sasl-2.1.18-r2"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200410-05] Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cyrus-SASL: Buffer overflow and SASL_PATH vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-libs/cyrus-sasl", unaffected: make_list("ge 2.1.18-r2"), vulnerable: make_list("le 2.1.18-r1")
)) { security_hole(0); exit(0); }
