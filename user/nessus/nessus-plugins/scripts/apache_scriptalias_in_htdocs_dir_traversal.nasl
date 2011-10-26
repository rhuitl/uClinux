#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by an information disclosure issue. 

Description :

The version of Apache for Windows installed on the remote host can be
tricked into disclosing the source of its CGI scripts because of a
configuration issue.  Specifically, if the CGI directory is located
within the document root, then requests that alter the case of the
directory name will bypass the mod_cgi cgi-script handler and be
treated as requests for ordinary files. 

See also :

http://www.securityfocus.com/archive/1/442882/30/0/threaded

Solution :

Reconfigure Apache so that the scripts directory is located outside of
the document root. 

Risk factor :

Low / CVSS Base Score : 2 
(AV:R/AC:H/Au:NR/C:P/A:N/I:N/B:N)";


if (description)
{
  script_id(22203);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-4110");
  script_bugtraq_id(19447);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27913");

  script_name(english:"Apache for Windows CGI Source Code Disclosure Vulnerability");
  script_summary(english:"Tries to read source of print-env.pl with Apache for Windows");

  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from Apache.
#
# nb: if ServerTokens is set to anything other than "OS" or "Full",
#     it won't tell us that it's running under Windows.
banner = get_http_banner(port:port);
if (!banner || "Apache" >!< banner ) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw to read a CGI script.
  #
  # nb: printenv.pl is included by default.
  file = "printenv.pl";
  req = http_get(item:string(toupper(dir), "/", file), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like the source.
  if (
    "foreach $var (sort(keys(%ENV))) {" >< res &&
    egrep(pattern:"^#!.+/perl\.exe", string:res)
  )
  {
    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the '", dir, "/", file, "' CGI script that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      res
    );

    security_hole(port:port, data:report);
    exit(0);
  }
}
