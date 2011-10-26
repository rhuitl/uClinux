#TRUSTED 0e071404129e82d994aa700dffd189c50d85d44fdd5af1f75c01151a9effbea0a3637ba73c47494b728eb60ec7f0f9a0bd1695d3d13d6e64846a378204c21d8649133f02defd1fed3b80965cb337b1f0c4e6ec453af504febdd243fa9773d456a48f77a3181cc1fc5bf13f1739a45e19e373038a5dce3b39cf6ac5c7badeea255de0e3d0d39bc930f9ad844293f3ac934f77e60079269f33dee9250b794b21655a3681822972399d6e6c9fd2643e81fcd9c046d4d9044fd80141b2ce9a72047f9b5f6d3e14e93b0d74aa93188baa1bbfb2c313bc8909ce6c3095371ffc789b8a05a48ba9cb883e7a7007bbb5417f840cecadc563b78c7d10a95ce9eac4eeacd8b93b6fe1f0d5a7c8170fe5f12d18b0a7377307cc9d2cce6790c3a33dbe9f7d065672d07e67337d2e83bd1cfcc0c3fc22c815f84122dce9d4c75c6b92f03505d7adcd2b9e2c1be57ad0881648a4f405c972b1382fed9ce0a46f2d6efc1983c02776caea6470dd859f2b5583e07ca066041170d62a837ffb504bd356ddf12e9a2f979fd0b62a2b6a1d2e6e12bf67e80ba06a9a11f87e11c82addc56dea5aaa4ef0703deeda96823f81a6da8b8c26002f376ef25c933df9a39c6de330db3c8ddc223fd1f759d1fc7ea3b0f8c4acbd70ae01968e7f1bfa2c20ecbf0a47ce0098f0057598095a45f66369e14b3d0a8b3d6028bbc5f6f7d962783694d074afbfb35a3e
#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# GPL
#

if (! defined_func("script_get_preference_file_location")) exit(0);
if (! find_in_path("hydra") ) exit(0);


if(description)
{
 script_id(15886);
 script_version ("1.2");
 name["english"] = "Hydra: SNMP";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin runs Hydra to find SNMP passwords by brute force.

See the section 'plugins options' to configure it
";

 script_description(english:desc["english"]);
 
 summary["english"] = "Brute force SNMP authentication with Hydra";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2004 Michel Arboi");
 script_family(english:"Brute force attacks");
 script_require_keys("Secret/hydra/passwords_file");
 script_require_udp_ports(161, 32789);
 script_dependencies("hydra_options.nasl", "snmp_settings.nasl");
 exit(0);
}

#

throrough = get_kb_item("global_settings/thorough_tests");
if ("yes" >!< throrough) exit(0);
passwd = get_kb_item("Secret/hydra/passwords_file");
if (passwd == NULL) exit(0);

port = get_kb_item("SNMP/port");
if (port) exit(0);
# Yes! We exit if we know the port, and thus some common community name
port = 161;
if (! get_udp_port_state(port)) exit(0);

timeout = get_kb_item("/tmp/hydra/timeout"); timeout = int(timeout);
tasks = get_kb_item("/tmp/hydra/tasks"); task = int(tasks);

empty = get_kb_item("/tmp/hydra/empty_password");
exit_asap = get_kb_item("/tmp/hydra/exit_ASAP");

i = 0;
argv[i++] = "hydra";
argv[i++] = "-s"; argv[i++] = port;
argv[i++] = "-P"; argv[i++] = passwd;
if (empty)
if (s)
{
  argv[i++] = "-e"; argv[i++] = "n";
}
if (exit_asap) argv[i++] = "-f";

if (timeout > 0)
{
  argv[i++] = "-w";
  argv[i++] = timeout;
}
if (tasks > 0)
{
  argv[i++] = "-t";
  argv[i++] = tasks;
}

argv[i++] = get_host_ip();
argv[i++] = "snmp";

report = "";
results = pread(cmd: "hydra", argv: argv, nice: 5);
foreach line (split(results))
{
  v = eregmatch(string: line, pattern: 'host:.*(login: *.*)? password: *(.*)$');
  if (! isnull(v))
  {
    p = chomp(v[2]);
    report = strcat(report, p, '\n');
    set_kb_item(name: 'Hydra/snmp/'+port, value: p);
  }
}

if (report)
  security_hole(port: port, 
    data: 'Hydra was able to break the following SNMP communities:\n' + report);
