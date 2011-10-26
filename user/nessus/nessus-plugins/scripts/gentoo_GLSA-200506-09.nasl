# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-09.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(18466);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200506-09");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200506-09
(gedit: Format string vulnerability)


    A format string vulnerability exists when opening files with names
    containing format specifiers.
  
Impact

    A specially crafted file with format specifiers in the filename
    can cause arbitrary code execution.
  
Workaround

    There are no known workarounds at this time.
  
References:
    http://www.securityfocus.com/bid/13699
    http://mail.gnome.org/archives/gnome-announce-list/2005-June/msg00006.html


Solution: 
    All gedit users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-editors/gedit-2.10.3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200506-09] gedit: Format string vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'gedit: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "app-editors/gedit", unaffected: make_list("ge 2.10.3"), vulnerable: make_list("lt 2.10.3")
)) { security_warning(0); exit(0); }
