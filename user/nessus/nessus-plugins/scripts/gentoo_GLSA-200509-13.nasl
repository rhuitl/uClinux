# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-13.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(19812);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200509-13");
 script_cve_id("CVE-2005-2919", "CVE-2005-2920");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200509-13
(Clam AntiVirus: Multiple vulnerabilities)


    Clam AntiVirus is vulnerable to a buffer overflow in
    "libclamav/upx.c" when processing malformed UPX-packed executables. It
    can also be sent into an infinite loop in "libclamav/fsg.c" when
    processing specially-crafted FSG-packed executables.
  
Impact

    By sending a specially-crafted file an attacker could execute
    arbitrary code with the permissions of the user running Clam AntiVirus,
    or cause a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2919
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-2920
    http://sourceforge.net/project/shownotes.php?release_id=356974


Solution: 
    All Clam AntiVirus users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.87"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200509-13] Clam AntiVirus: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Clam AntiVirus: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.87"), vulnerable: make_list("lt 0.87")
)) { security_hole(0); exit(0); }
