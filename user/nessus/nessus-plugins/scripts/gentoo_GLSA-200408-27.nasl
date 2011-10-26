# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-27.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14583);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200408-27");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200408-27
(Gaim: New vulnerabilities)


    Gaim fails to do proper bounds checking when:
    Handling MSN messages (partially fixed with GLSA 200408-12).
    Handling rich text format messages.
    Resolving local hostname.
    Receiving long URLs.
    Handling groupware messages.
    Allocating memory for webpages with fake content-length header.
    Furthermore Gaim fails to escape filenames when using drag and drop
    installation of smiley themes.
  
Impact

    These vulnerabilites could allow an attacker to crash Gaim or execute
    arbitrary code or commands with the permissions of the user running Gaim.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of Gaim.
  
References:
    http://gaim.sourceforge.net/security/index.php


Solution: 
    All gaim users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-im/gaim-0.81-r5"
    # emerge ">=net-im/gaim-0.81-r5"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200408-27] Gaim: New vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: New vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 0.81-r5"), vulnerable: make_list("lt 0.81-r5")
)) { security_warning(0); exit(0); }
