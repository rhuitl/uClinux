#
# (C) Tenable Network Security
#


if (description) {
  script_id(18416);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2005-1875");
  script_bugtraq_id(13844);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"17006");
  }

  name["english"] = "Exhibit Engine list.php SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is vulnerable to
SQL injection attacks. 

Description :

The remote host is running Exhibit Engine, a web-based photo gallery
written in PHP. 

The version installed on the remote host suffers from a SQL injection
vulnerability due to its failure to sanitize user-supplied input to
various parameters of the 'list.php' script.  An attacker can exploit
these flaws to inject arbitrary SQL statements into the affected
application, possibly even reading arbitrary database entries. 

See also : 

http://www.sec-consult.com/176.html
http://archives.neohapsis.com/archives/fulldisclosure/2005-06/0007.html
http://photography-on-the.net/forum/showthread.php?p=579692

Solution : 

Upgrade if necessary to EE 1.5RC4 and apply the patched
'slashwork.php' script referenced in the second URL above. 

Risk factor : 

Medium / CVSS Base Score : 5
(AV:R/AC:L/Au:NR/C:P/A:N/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for SQL injection vulnerability in Exhibit Engine's list.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/list.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's from Exhibit Engine...
  if (egrep(string:res, pattern:'href="http://photography-on-the\\.net/ee/?" title=".*Exhibit Engine')) {
    # Try to exploit the flaw.
    #
    # nb: this will fail if there are no public exhibitions.
    postdata = string(
      # nb: try to cause a syntax error with the single quote.
      "search_row=ee_photo.ee_photo_exif_text'&",
      "keyword=", SCRIPT_NAME
    );
    req = string(
      "POST ", dir, "/list.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if we see a syntax error.
    if (
      (
        # versions 1.5 and above.
        ">Exhibit Engine MySQL error!</big><br>ERROR FROM QUERY" >< res ||
        # versions 1.3 and earlier.
        ">An error in retrieving data from database was reported by EE<" >< res
      ) &&
      egrep(string:res, pattern:string("(SQL syntax|syntax to use) near '\\\\' LIKE '%", SCRIPT_NAME))
    ) {
      security_warning(port);
      exit(0);
    }
  }
}
