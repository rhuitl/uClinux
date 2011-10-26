# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-22.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21742);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200606-22");
 script_cve_id("CVE-2006-2916");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200606-22
(aRts: Privilege escalation)


    artswrapper fails to properly check whether it can drop privileges
    accordingly if setuid() fails due to a user exceeding assigned resource
    limits.
  
Impact

    Local attackers could exploit this vulnerability to execute arbitrary
    code with elevated privileges. Note that the aRts package provided by
    Gentoo is only vulnerable if the artswrappersuid USE-flag is enabled.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2916


Solution: 
    All aRts users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose kde-base/arts
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200606-22] aRts: Privilege escalation");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'aRts: Privilege escalation');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "kde-base/arts", unaffected: make_list("ge 3.5.2-r1", "rge 3.4.3-r1"), vulnerable: make_list("lt 3.5.2-r1")
)) { security_hole(0); exit(0); }
