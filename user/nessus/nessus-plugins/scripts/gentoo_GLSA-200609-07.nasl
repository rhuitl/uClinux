# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200609-07.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(22352);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200609-07");
 script_cve_id("2006-3739", "2006-3740");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200609-07
(LibXfont, monolithic X.org: Multiple integer overflows)


    Several integer overflows have been found in the CID font parser.
  
Impact

    A remote attacker could exploit this vulnerability by enticing a user
    to load a malicious font file resulting in the execution of arbitrary
    code with the permissions of the user running the X server which
    typically is the root user. A local user could exploit this
    vulnerability to gain elevated privileges.
  
Workaround

    Disable CID-encoded Type 1 fonts by removing the "type1" module and
    replacing it with the "freetype" module in xorg.conf.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-3739
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-3740


Solution: 
    All libXfont users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=x11-libs/libXfont-1.2.1"
    All monolithic X.org users are advised to migrate to modular X.org.
  

Risk factor : High
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200609-07] LibXfont, monolithic X.org: Multiple integer overflows");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LibXfont, monolithic X.org: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "x11-base/xorg-x11", unaffected: make_list("ge 7.0"), vulnerable: make_list("lt 7.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "x11-libs/libXfont", unaffected: make_list("ge 1.2.1"), vulnerable: make_list("lt 1.2.1")
)) { security_hole(0); exit(0); }
