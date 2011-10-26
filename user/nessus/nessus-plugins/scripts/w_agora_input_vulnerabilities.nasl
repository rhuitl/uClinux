#
# (C) Tenable Network Security
#

if (description) {
  script_id(15402);
  script_cve_id(
    "CVE-2004-1562",
    "CVE-2004-1563",
    "CVE-2004-1564",
    "CVE-2004-1565"
  );
  script_bugtraq_id(11283);
  script_version("$Revision: 1.6 $");
 
  name["english"] = "w-Agora Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running w-agora, a web-based forum management software
written in PHP.

There are multiple input validation flaws in the remote version of this 
software :

- There is an SQL injection vulnerability in the file 'redir_url.php' which
may allow an attacker to execute arbitrary SQL statements in the remote 
database ;

- There is a cross site scripting issue which may allow an attacker to
steal the cookies of the legitimate users of the remote site by sending them
a specially malformed link ;

- There is an HTTP response splitting vulnerability which may also allow
an attacker to perform cross-site scripting attacks against the remote host.

Solution : Upgrade to the newest version of this software
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for vulnerabilities in w-Agora";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


function check(req)
{
  host = get_host_name();
  variables = "loginuser=<script>foo</script>&loginpassword=foo&btnlogin=Login";
  req = string("POST ", req, " HTTP/1.1\r\n", 
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("<script>foo</script>" >< buf && "w-agora" >< buf )
  	{
	security_hole(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach dir (cgi_dirs()) 
 {
  if ( is_cgi_installed_ka(item:dir + "/login.php", port:port) ) check(req:dir + "/login.php");
 }
