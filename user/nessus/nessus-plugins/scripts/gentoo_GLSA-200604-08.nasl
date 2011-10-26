# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200604-08.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(21254);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200604-08");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200604-08
(libapreq2: Denial of Service vulnerability)


    A vulnerability has been reported in the apreq_parse_headers() and
    apreq_parse_urlencoded() functions of Apache2::Request.
  
Impact

    A remote attacker could possibly exploit the vulnerability to
    cause a Denial of Service by CPU consumption.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0042
    http://svn.apache.org/viewcvs.cgi/httpd/apreq/tags/v2_07/CHANGES?rev=376998&view=markup


Solution: 
    All libapreq2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apache/libapreq2-2.07"
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200604-08] libapreq2: Denial of Service vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libapreq2: Denial of Service vulnerability');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-apache/libapreq2", unaffected: make_list("ge 2.07"), vulnerable: make_list("lt 2.07")
)) { security_warning(0); exit(0); }
