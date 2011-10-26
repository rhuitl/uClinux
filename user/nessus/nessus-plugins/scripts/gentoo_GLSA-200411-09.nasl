# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15634);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-09");
 script_cve_id("CVE-2004-1001");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-09
(shadow: Unauthorized modification of account information)


    Martin Schulze reported a flaw in the passwd_check() function in
    "libmisc/pwdcheck.c" which is used by chfn and chsh.
  
Impact

    A logged-in local user with an expired password may be able to use chfn and
    chsh to change his standard shell or GECOS information (full name, phone
    number...) without being required to change his password.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://ftp.pld.org.pl/software/shadow/NEWS
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1001


Solution: 
    All shadow users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=sys-apps/shadow-4.0.5-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-09] shadow: Unauthorized modification of account information");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'shadow: Unauthorized modification of account information');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "sys-apps/shadow", unaffected: make_list("ge 4.0.5-r1"), vulnerable: make_list("lt 4.0.5-r1")
)) { security_warning(0); exit(0); }
