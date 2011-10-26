# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-20.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16471);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200502-20");
 script_cve_id("CVE-2005-0100");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-20
(Emacs, XEmacs: Format string vulnerabilities in movemail)


    Max Vozeler discovered that the movemail utility contains several
    format string errors.
  
Impact

    An attacker could set up a malicious POP server and entice a user
    to connect to it using movemail, resulting in the execution of
    arbitrary code with the rights of the victim user.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0100


Solution: 
    All Emacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/emacs-21.4"
    All XEmacs users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/xemacs-21.4.15-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-20] Emacs, XEmacs: Format string vulnerabilities in movemail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Emacs, XEmacs: Format string vulnerabilities in movemail');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-editors/xemacs", unaffected: make_list("ge 21.4.15-r3"), vulnerable: make_list("lt 21.4.15-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-editors/emacs", unaffected: make_list("ge 21.4"), vulnerable: make_list("lt 21.4")
)) { security_warning(0); exit(0); }
