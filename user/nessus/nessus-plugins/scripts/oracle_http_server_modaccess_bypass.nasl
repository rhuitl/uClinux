#
# (C) Tenable Network Security
#


if (description) {
  script_id(18181);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1383");
  script_bugtraq_id(13418);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"15908");

  name["english"] = "Oracle HTTP Server mod_access Restriction Bypass Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure
vulnerability. 

Description :

The version of Oracle HTTP Server (OHS) installed on the remote host
fails to prevent users from accessing protected URLs by using the Web
Cache rather than OHS directly. 

See also : 

http://www.red-database-security.com/advisory/oracle_webcache_bypass.html
http://archives.neohapsis.com/archives/bugtraq/2005-04/0486.html

Solution : 

Enable 'UseWebCacheIP' in OHS's httpd.conf.

Risk factor : 

Low / CVSS Base Score : 1
(AV:R/AC:H/Au:R/C:P/A:N/I:N/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for mod_access restriction bypass vulnerability in Oracle HTTP Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7777, 7778);
  script_require_keys("www/OracleApache");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


# We need to locate both OHS and Web Cache.
list = get_kb_list("Services/http");
if (isnull(list)) exit(0);
list = make_list(list);
foreach port (list) {
  banner = get_http_banner(port:port);

  # nb: the banner for Web Cache likely includes the string 
  #     "Oracle-HTTP-Server" as well so check for it first.
  if (banner && "OracleAS-Web-Cache" >< banner) webcache_port = port;
  else if (banner && "Oracle-HTTP-Server" >< banner) ohs_port = port;
  if (webcache_port && ohs_port) break;
}
if (!webcache_port || !ohs_port) exit(0);
if (!get_port_state(webcache_port) || !get_port_state(ohs_port)) exit(0);
if (get_kb_item("www/no404/" + webcache_port)) exit(0);


# Try to access some normally protected URIs.
uris = make_list(
  '/dms0',
  '/dmsoc4j/AggreSpy?format=metrictable&nountype=ohs_child&orderby=Name',
  '/server-status'
);
foreach uri (uris) {
  # Try to access them first through OHS to make sure that they
  # exist and are protected.
  req = http_get(item:"uri", port:ohs_port);
  res = http_keepalive_send_recv(port:ohs_port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);
  if (!egrep(string:res, pattern:"^HTTP/.* 403 Forbidden")) continue;

  # Now try going through Web Cache.
  req = http_get(item:"uri", port:webcache_port);
  res = http_keepalive_send_recv(port:webcache_port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # It's a problem if this worked.
  if (!egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
    security_note(ohs_port);
    exit(0);
  }
}
