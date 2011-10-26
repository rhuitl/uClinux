# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-10.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14461);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200403-10");
 script_cve_id("CVE-2003-0792");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-10
(Fetchmail 6.2.5 fixes a remote DoS)


    Fetchmail versions 6.2.4 and earlier can be crashed by sending a
    specially-crafted email to a fetchmail user. This problem occurs because
    Fetchmail does not properly allocate memory for long lines in an incoming
    email.
  
Impact

    Fetchmail users who receive a malicious email may have their fetchmail
    program crash.
  
Workaround

    While a workaround is not currently known for this issue, all users are advised to upgrade to the latest version of fetchmail.
  
References:
    http://xforce.iss.net/xforce/xfdb/13450
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-0792


Solution: 
    Fetchmail users should upgrade to version 6.2.5 or later:
    # emerge sync
    # emerge -pv ">=net-mail/fetchmail-6.2.5"
    # emerge ">=net-mail/fetchmail-6.2.5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-10] Fetchmail 6.2.5 fixes a remote DoS");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Fetchmail 6.2.5 fixes a remote DoS');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-mail/fetchmail", unaffected: make_list("ge 6.2.5"), vulnerable: make_list("le 6.2.4")
)) { security_warning(0); exit(0); }
