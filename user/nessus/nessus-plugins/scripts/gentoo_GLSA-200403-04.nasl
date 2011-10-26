# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2005 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004 Michel Arboi <mikhail@nessus.org>

if (! defined_func('bn_random')) exit(0);

if (description)
{
 script_id(14455);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200403-04");

 desc = 'The remote host is affected by the vulnerability described in GLSA-200403-04
(Multiple security vulnerabilities in Apache 2)


    Three vulnerabilities were found:
        A memory leak in ssl_engine_io.c for mod_ssl in Apache 2.0.48 and below
        allows remote attackers to cause a denial of service attack
        via plain HTTP requests to the SSL port of an SSL-enabled server.
        Apache fails to filter terminal escape sequences from error
        logs that begin with the ASCII (0x1B) sequence and are followed by a
        series of arguments. If a remote attacker could inject escape sequences
        into an Apache error log, the attacker could take advantages of
        weaknesses in various terminal emulators, launching attacks
        against remote users including further denial of service attacks,
        file modification, and the execution of arbitrary commands.
        The Apache mod_disk_cache has been found to be
        vulnerable to a weakness that allows attackers to gain access
        to authentication credentials through the issue of caching
        HTTP hop-by-hop headers which would contain plaintext user
        passwords. There is no available resolution for this issue yet.
  
Impact

    No special privileges are required for these vulnerabilities. As a result,
    all users are recommended to upgrade their Apache installations.
  
Workaround

    There is no immediate workaround; a software upgrade is required.
    There is no workaround for the mod_disk_cache issue; users are
    recommended to disable the feature on their servers until a patched
    version is released.
  
References:
    http://www.securityfocus.com/bid/9933/info/
    http://www.apache.org/dist/httpd/Announcement2.html


Solution: 
    Users are urged to upgrade to Apache 2.0.49:
    # emerge sync
    # emerge -pv ">=net-www/apache-2.0.49"
    # emerge ">=net-www/apache-2.0.49"
    # ** IMPORTANT **
    # If you are migrating from Apache 2.0.48-r1 or earlier versions,
    # it is important that the following directories are removed.
    # The following commands should cause no data loss since these
    # are symbolic links.
    # rm /etc/apache2/lib /etc/apache2/logs /etc/apache2/modules
    # rm /etc/apache2/extramodules
    # ** ** ** ** **
    # ** ALSO NOTE **
    # Users who use mod_disk_cache should edit their Apache
    # configuration and disable mod_disk_cache.
  

Risk factor : Medium
';
 script_description(english: desc);
 script_copyright(english: "(C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[GLSA-200403-04] Multiple security vulnerabilities in Apache 2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple security vulnerabilities in Apache 2');
 exit(0);
}

include('qpkg.inc');
if (qpkg_check(package: "net-www/apache", unaffected: make_list("eq 1.3*", "ge 2.0.49"), vulnerable: make_list("le 2.0.48")
)) { security_warning(0); exit(0); }
