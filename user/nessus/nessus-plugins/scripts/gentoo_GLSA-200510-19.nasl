# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-19.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(20081);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200510-19");
 script_cve_id("CVE-2005-3185");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200510-19
(cURL: NTLM username stack overflow)


    iDEFENSE reported that insufficient bounds checking on a memcpy()
    of the supplied NTLM username can result in a stack overflow.
  
Impact

    A remote attacker could setup a malicious server and entice an
    user to connect to it using a cURL client, potentially leading to the
    execution of arbitrary code with the permissions of the user running
    cURL.
  
Workaround

    Disable NTLM authentication by not using the --anyauth or --ntlm
    options when using cURL (the command line version). Workarounds for
    programs that use the cURL library depend on the configuration options
    presented by those programs.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3185
    http://www.idefense.com/application/poi/display?id=322&type=vulnerabilities


Solution: 
    All cURL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/curl-7.15.0"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200510-19] cURL: NTLM username stack overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'cURL: NTLM username stack overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-misc/curl", unaffected: make_list("ge 7.15.0"), vulnerable: make_list("lt 7.15.0")
)) { security_warning(0); exit(0); }
