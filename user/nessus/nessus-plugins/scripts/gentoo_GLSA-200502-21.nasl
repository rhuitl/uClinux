# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-21.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(16472);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200502-21");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200502-21
(lighttpd: Script source disclosure)


    lighttpd uses file extensions to determine which elements are
    programs that should be executed and which are static pages that should
    be sent as-is. By appending %00 to the filename, you can evade the
    extension detection mechanism while still accessing the file.
  
Impact

    A remote attacker could send specific queries and access the
    source of scripts that should have been executed as CGI or FastCGI
    applications.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://article.gmane.org/gmane.comp.web.lighttpd/1171


Solution: 
    All lighttpd users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/lighttpd-1.3.10-r1"
  

Risk factor : Low
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200502-21] lighttpd: Script source disclosure");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'lighttpd: Script source disclosure');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "www-servers/lighttpd", unaffected: make_list("ge 1.3.10-r1"), vulnerable: make_list("lt 1.3.10-r1")
)) { security_warning(0); exit(0); }
