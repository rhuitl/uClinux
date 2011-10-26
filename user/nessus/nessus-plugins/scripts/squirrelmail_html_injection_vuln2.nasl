#
# (C) Tenable Network Security
#

if (description) {
  script_id(15718);
  script_bugtraq_id(11653,12413);
  script_version ("$Revision: 1.2 $");

  name["english"] = "SquirrelMail decodeHeader HTML injection vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running SquirrelMail, a webmail system written in PHP. 

Versions of SquirrelMail prior to 1.4.4 are vulnerable to an email HTML 
injection vulnerability. A remote attacker can exploit this flaw to gain 
access to the users' accounts.

Solution : Upgrade to the newest version of this software
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Check Squirrelmail for HTML injection vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("squirrelmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) 
	exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/squirrelmail"));
if (isnull(installs)) 
	exit(0);

foreach install (installs) 
{
	matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  	if (!isnull(matches)) 
	{
    		ver = matches[1];
    		dir = matches[2];

    		if (ereg(pattern:"^(0\..*|1\.([0-3]\..*|4\.[0-3][^0-9]))$", string:ver)) 
		{
      			security_hole(port);
      			exit(0);
    		}
  	}
}


