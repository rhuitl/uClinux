# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-02.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15590);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200411-02");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-02
(Cherokee: Format string vulnerability)


    Florian Schilhabel from the Gentoo Linux Security Audit Team found a format
    string vulnerability in the cherokee_logger_ncsa_write_string() function.
  
Impact

    Using a specially crafted URL when authenticating via auth_pam, a malicious
    user may be able to crash the server or execute arbitrary code on the
    target machine with permissions of the user running Cherokee.
  
Workaround

    There is no known workaround at this time.
  

Solution: 
    All Cherokee users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/cherokee-0.4.17.1"
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-02] Cherokee: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cherokee: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-servers/cherokee", unaffected: make_list("ge 0.4.17.1"), vulnerable: make_list("le 0.4.17")
)) { security_hole(0); exit(0); }
