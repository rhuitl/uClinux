# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-28.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14791);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-28");
 script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-28
(GTK+ 2, gdk-pixbuf: Multiple image decoding vulnerabilities)


    A vulnerability has been discovered in the BMP image preprocessor
    (CVE-2004-0753). Furthermore, Chris Evans found a possible integer overflow
    in the pixbuf_create_from_xpm() function, resulting in a heap overflow
    (CVE-2004-0782). He also found a potential stack-based buffer overflow in
    the xpm_extract_color() function (CVE-2004-0783). A possible integer
    overflow has also been found in the ICO decoder.
  
Impact

    With a specially crafted BMP image an attacker could cause an affected
    application to enter an infinite loop when that image is being processed.
    Also, by making use of specially crafted XPM or ICO images an attacker
    could trigger the overflows, which potentially allows the execution of
    arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0753
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0782
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0783
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0788
    http://bugzilla.gnome.org/show_bug.cgi?id=150601


Solution: 
    All GTK+ 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=x11-libs/gtk+-2.4.9-r1"
    # emerge ">=x11-libs/gtk+-2.4.9-r1"
    All GdkPixbuf users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/gdk-pixbuf-0.22.0-r3"
    # emerge ">=media-libs/gdk-pixbuf-0.22.0-r3"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-28] GTK+ 2, gdk-pixbuf: Multiple image decoding vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GTK+ 2, gdk-pixbuf: Multiple image decoding vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "media-libs/gdk-pixbuf", unaffected: make_list("ge 0.22.0-r3"), vulnerable: make_list("lt 0.22.0-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "x11-libs/gtk+", unaffected: make_list("ge 2.4.9-r1", "lt 2.0.0"), vulnerable: make_list("lt 2.4.9-r1")
)) { security_warning(0); exit(0); }
