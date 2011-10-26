# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14766);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200409-21");
 script_cve_id("CVE-2004-0747", "CVE-2004-0748", "CVE-2004-0751", "CVE-2004-0786", "CVE-2004-0809");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200409-21
(Apache 2, mod_dav: Multiple vulnerabilities)


    A potential infinite loop has been found in the input filter of mod_ssl
    (CVE-2004-0748) as well as a possible segmentation fault in the
    char_buffer_read function if reverse proxying to a SSL server is being used
    (CVE-2004-0751). Furthermore, mod_dav, as shipped in Apache httpd 2 or
    mod_dav 1.0.x for Apache 1.3, contains a NULL pointer dereference which can
    be triggered remotely (CVE-2004-0809). The third issue is an input
    validation error found in the IPv6 URI parsing routines within the apr-util
    library (CVE-2004-0786). Additionally a possible buffer overflow has been
    reported when expanding environment variables during the parsing of
    configuration files (CVE-2004-0747).
  
Impact

    A remote attacker could cause a Denial of Service either by aborting a SSL
    connection in a special way, resulting in CPU consumption, by exploiting
    the segmentation fault in mod_ssl or the mod_dav flaw. A remote attacker
    could also crash a httpd child process by sending a specially crafted URI.
    The last vulnerabilty could be used by a local user to gain the privileges
    of a httpd child, if the server parses a carefully prepared .htaccess file.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0747
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0748
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0751
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0786
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0809


Solution: 
    All Apache 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/apache-2.0.51"
    # emerge ">=net-www/apache-2.0.51"
    All mod_dav users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/mod_dav-1.0.3-r2"
    # emerge ">=net-www/mod_dav-1.0.3-r2"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200409-21] Apache 2, mod_dav: Multiple vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2, mod_dav: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/mod_dav", unaffected: make_list("ge 1.0.3-r2"), vulnerable: make_list("le 1.0.3-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-www/apache", unaffected: make_list("ge 2.0.51", "lt 2.0"), vulnerable: make_list("lt 2.0.51")
)) { security_warning(0); exit(0); }
