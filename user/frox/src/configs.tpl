# Configuration variables.

# This file is parsed along with configs.c.in by configen.pl, and
# produces the config file parsing code. CL is the command line
# option, RELOAD is whether the option is reloadable on SIGHUP, and
# NEED is whether the option must be specified. If defaults are not
# specified here they will be 0.
#
# NB. chroot is set to type STRING not DIR -- we do not want it to be 
# stripped on chroot.

# NAME             TYPE     VARIABLE   CL RELOAD NEED DEFAULT
#
  -               FILENAME config_file  f FALSE FALSE -
  Listen          ADDRESS  listen       - FALSE FALSE -
  Port            INT      lport        p FALSE TRUE  -
  ResolvLoadHack  STRING   resolvhack   - FALSE FALSE NULL
  BindToDevice    STRING   device       - FALSE FALSE NULL
  FromInetd       BOOL     inetd        i FALSE FALSE -
  NoDetach        BOOL     nodetach     N FALSE FALSE -
  FTPProxy        ADDRPRT  ftpproxy     - TRUE  FALSE -
  FTPProxyNoPort  BOOL     ftpproxynp   - TRUE  FALSE -
  ControlPorts    PRTRNGE  contports    - TRUE  FALSE 40000-50000
  PassivePorts    PRTRNGE  pasvports    - TRUE  FALSE 40000-50000
  ActivePorts     PRTRNGE  actvports    - TRUE  FALSE 40000-50000
  Timeout         INT      timeout      - TRUE  FALSE 300
  MaxForks        INT      maxforks     m TRUE  FALSE -
  MaxForksPerHost INT      maxforksph   - TRUE  FALSE -
  MaxTransferRate INT      maxdlrate    - TRUE  FALSE -
  CacheDlRate     INT      cachedlrate  - TRUE  FALSE -
  MaxUploadRate   INT      maxulrate    - TRUE  FALSE -
  User            STRING   user         - FALSE TRUE  NULL
  Group           STRING   group        - FALSE TRUE  NULL
  WorkingDir      STRING   chroot       - FALSE TRUE  -
  DontChroot      BOOL     dontchroot   - FALSE FALSE -
  AllowNonAscii   BOOL     nonasciiok   - TRUE  FALSE FALSE
  BounceDefend    BOOL     bdefend      - TRUE  FALSE TRUE
  SameAddress     BOOL     sameaddress  - TRUE  FALSE -
  LogFile         FILENAME logfile      - FALSE FALSE -
  LogLevel        INT      loglevel     l TRUE  FALSE 15
  XferLogging     BOOL     xferlogging  - TRUE  FALSE TRUE
  PidFile         FILENAME pidfile      - FALSE FALSE -
  APConv          BOOL     apconv       - TRUE  FALSE -
  PAConv          BOOL     paconv       - TRUE  FALSE -
  DoNTP           BOOL     ntp          - TRUE  FALSE -
  NTPAddress      ADDRPRT  ntpdest      - TRUE  FALSE -
  TcpOutgoingAddr ADDRESS  tcpoutaddr   - TRUE  FALSE -
  PASVAddress     ADDRESS  pasvaddress  - TRUE  FALSE -
  ACL             ACL      acls         - TRUE  FALSE -
  SubSection      SUBSECT  subsecs      - TRUE  FALSE -
ifdef TRANS_DATA
  TransparentData BOOL     transdata    - FALSE FALSE -
endif
ifdef USE_CACHE
  CacheModule     STRING   cachemod     - FALSE FALSE NULL
  CacheSize       INT      cachesize    - FALSE FALSE -
  HTTPProxy       ADDRPRT  httpproxy    - TRUE  FALSE -
  ForceHTTP       BOOL     forcehttp    - TRUE  FALSE -
  MinCacheSize    INT      mincachesize - TRUE  FALSE -
  StrictCaching   BOOL     strictcache  - TRUE  FALSE -
  CacheOnFQDN     BOOL     usefqdn      - TRUE  FALSE -
  CacheAll        BOOL     cacheall     - TRUE  FALSE -
endif
ifdef USE_CCP
  CCProgram       FILENAME ccpcmd       - TRUE  FALSE NULL
  UseOldCCP       BOOL     oldccp       - TRUE  FALSE TRUE
endif
ifdef DO_VSCAN
  VirusScanner    STRING   vscanner     - TRUE  FALSE NULL
  VSOK            INT      vscanok      - TRUE  FALSE 0
  VSProgressMsgs  INT      vscanpm      - TRUE  FALSE 0
endif
ifdef DO_SSL
  UseSSL          BOOL     usessl       - TRUE  FALSE -
  DataSSL         BOOL     datassl      - TRUE  FALSE TRUE
  AnonSSL         BOOL     anonssl      - TRUE  FALSE TRUE
endif

# Where an option needs further processing (eg. group --> gid) then
# this is written manually in process_opts() in configs.c. Any extra
# variables for this (eg. config.gid) are specified manually in the
# struct options declaration in configs.h.
