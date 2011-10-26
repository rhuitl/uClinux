#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: SecuBox fRoGGz <unsecure@writeme.com>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(18216);

  script_cve_id("CVE-2005-1509");
  script_bugtraq_id(13561, 13563);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16233");
  }

  script_version("$Revision: 1.6 $");
  script_name(english:"PWSPHP XSS");

  desc["english"] = "
The remote host runs PWSPHP (Portail Web System) a CMS written in PHP.

The remote version  of this software is vulnerable to cross-site 
scripting attack due to a lack of sanity checks on the 'skin' parameter
in the script SettingsBase.php.

With a specially crafted URL, an attacker could use the remote server
to set up a cross site script attack.

Solution: Upgrade to version 1.2.3 or newer
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks XSS in PWSPHP");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port)) exit(0);

if(get_port_state(port))
{
   foreach d ( cgi_dirs() )
   {
    buf = http_get(item:string(d,"/profil.php?id=1%20<script>foo</script>"), port:port);
    r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
    if( r == NULL )exit(0);
    if("title>PwsPHP " >< r && (egrep(pattern:"<script>foo</script>", string:r)))
    {
      security_warning(port);
      exit(0);
    }
   }
}
