# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(15619);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200411-08");
 script_cve_id("CVE-2004-0990");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200411-08
(GD: Integer overflow)


    infamous41md found an integer overflow in the memory allocation procedure
    of the GD routine that handles loading PNG image files.
  
Impact

    A remote attacker could entice a user to load a carefully crafted PNG image
    file in a GD-powered application, or send a PNG image to a web application
    which uses GD PNG decoding functions. This could potentially lead to
    execution of arbitrary code with the rights of the program loading the
    image.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.securityfocus.com/archive/1/379382
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0990


Solution: 
    All GD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gd-2.0.32"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200411-08] GD: Integer overflow");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GD: Integer overflow');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/gd", unaffected: make_list("ge 2.0.32"), vulnerable: make_list("lt 2.0.32")
)) { security_warning(0); exit(0); }
