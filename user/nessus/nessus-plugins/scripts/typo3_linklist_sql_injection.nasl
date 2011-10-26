#
# (C) Tenable Network Security
#


if (description) {
  script_id(17272);
  script_version ("$Revision: 1.4 $");

  script_cve_id("CVE-2005-0658");
  script_bugtraq_id(12721);

  name["english"] = "TYPO3 cmw_linklist Extension SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The installation of TYPO3 on the remote host is vulnerable to remote
SQL injection attacks through the parameter 'category_uid' used by the
third-party cmw_linklist extension.  By exploiting this flaw, a remote
attacker may be able to uncover sensitive information or even modify
existing data. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2005-03/0065.html
http://archives.neohapsis.com/archives/bugtraq/2005-03/0075.html
http://typo3.org/typo3-20050304-1.html

Solution : 

Upgrade to cmw_linklist extension version 1.5.0 or later.

Risk factor : 

Medium / CVSS Base Score : 5 
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects SQL injection vulnerability in TYPO3 CMW Linklist extension";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = make_list("/typo3", "/site", "/cms", cgi_dirs());
else dirs = make_list(cgi_dirs());

installs = 0;
foreach dir (dirs) {
  # Check if the extension is available.
  #
  # nb: the flaw is in pi1/class.tx_cmwlinklist_pi1.php so check for that.
  req = http_get(item:string(dir, "/typo3conf/ext/cmw_linklist/pi1/class.tx_cmwlinklist_pi1.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it is...
  if (res =~ "HTTP/.+ 200 OK") {
    # Grab the main page.
    req = http_get(item:string(dir, "/index.php"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # Find the Links page.
    #
    # nb: the actual text could be in the native language or even 
    #     set by the administrator making it hard to get a 
    #     robust pattern. :-(
    pat = '<a href="([^"]+)".+(Links</a>|name="links")';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      links = eregmatch(pattern:pat, string:match);
      if (!isnull(links)) {
        links = links[1];
        if (links !~ "^/") links = "/" + links;
        break;
      }
    }

    # Find a single link in the Links page (which should be local).
    if (!isnull(links) && links !~ "^http") {
      req = http_get(item:string(dir, links), port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      pat = '<A HREF="([^"]+&action=getviewcategory[^"]*">';
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        link = eregmatch(pattern:pat, string:match);
        if (!isnull(link)) {
          link = link[1];
          break;
        }
      }

      # Try to exploit vulnerability by issuing an impossible request.
      #
      # nb: The fix for the vulnerability evaluates category_uid as an 
      #     integer; thus, it's vulnerable if the result fails to
      #     return any links.
      if (link) {
        exploit = ereg_replace(
          string:link,
          pattern:"&category_uid=([0-9]+)",
          # cause query to fail by tacking " and 1=0 " onto the category_uid.
          replace:"\1%20and%201=0%20"
        );
        req = http_get(item:exploit, port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        # If there aren't any links, there's a problem.
        if (res !~ "&action=getviewclickedlink&uid=") {
          security_warning(port);
          exit(0);
        }
      }
    }
  }
}
