# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-15.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21096);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200603-15");
 script_cve_id("CVE-2006-0898");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200603-15
(Crypt::CBC: Insecure initialization vector)


    Lincoln Stein discovered that Crypt::CBC fails to handle 16 bytes
    long initializiation vectors correctly when running in the RandomIV
    mode, resulting in a weaker encryption because the second part of every
    block will always be encrypted with zeros if the blocksize of the
    cipher is greater than 8 bytes.
  
Impact

    An attacker could exploit weak ciphertext produced by Crypt::CBC
    to bypass certain security restrictions or to gain access to sensitive
    data.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0898


Solution: 
    All Crypt::CBC users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-perl/crypt-cbc-2.17"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200603-15] Crypt::CBC: Insecure initialization vector");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Crypt::CBC: Insecure initialization vector');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "dev-perl/crypt-cbc", unaffected: make_list("ge 2.17"), vulnerable: make_list("lt 2.17")
)) { security_warning(0); exit(0); }
