#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server is prone to a directory traversal vulnerability. 

Description :

The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee. 

According to its banner, the Common Management Agent on the remote
host can be used by an anonymous attacker to gain write access to any
file on the affected host with SYSTEM privileges. 

See also : 

http://research.eeye.com/html/advisories/published/AD20060713.html
http://knowledge.mcafee.com/article/640/9925498_f.SAL_Public.html

Solution :

Upgrade to version 3.5.5 or later of the Common Management Agent as
discussed in the vendor advisory above. 

Risk factor :

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:N/I:P/A:N/B:N)";


if (description)
{
  script_id(22046);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2006-3623");
  script_bugtraq_id(18979);
  if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"27158");

  script_name(english:"McAfee Common Management Agent Directory Traversal Vulnerability");
  script_summary(english:"Checks version of Common Management Agent");

  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8081);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8081);
if (!get_port_state(port)) exit(0);


# Grab the initial page.
res = http_get_cache(item:"/", port:port);
if (res == NULL) exit(0);


# If it looks like CMA...
if (
  '<?xml-stylesheet type="text/xsl" href="FrameworkLog.xsl"?>' >< res &&
  " <ePOServerName>" >< res
)
{
  # Extract the version number.
  pat = "^ +<version>([^<]+)</ver";
  ver = NULL;
  matches = egrep(pattern:pat, string:res);
  if (matches) {
    foreach match (split(matches))
    {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver))
      {
        ver = ver[1];
        break;
      }
    }
  }

  # There's a problem if it's under 3.5.5.438.
  #
  # nb: the version reported is the same as the file version of
  #     "Common Framework\FrakeworkService.exe", which is what matters.
  if (ver)
  {
    iver = split(ver, sep:'.', keep:FALSE);
    if (
      int(iver[0]) < 3 ||
      (
        int(iver[0]) == 3 &&
        (
          int(iver[1]) < 5 ||
          (
            int(iver[1]) == 5 &&
            (
              int(iver[2]) < 5 ||
              (int(iver[2]) == 5 && int(iver[3]) < 438)
            )
          )
        )
      )
    )
    {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "The version of the Common Management Agent on the remote host is\n",
        ver, ".\n"
      );
      security_note(port:port, data:report);
    }
  }
}
