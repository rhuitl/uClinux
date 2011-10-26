#! /bin/sh

SIZE=$(echo `wc -c < tests/test-insmod/02simple.sh`)
# Old options are ignored.
[ "`insmod -p tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -s tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -f tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -p -f -s tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]

# --version and -v
VERSION=`grep ^VERSION Makefile | sed 's/.*=[ 	]*//'`
[ "`insmod -V`" = "module-init-tools version $VERSION" ]
[ "`insmod --version`" = "module-init-tools version $VERSION" ]

# Don't try to quote or anything: we're not smart enough.
[ "`insmod tests/test-insmod/02simple.sh 'foo="baz bar"'`" = "INIT_MODULE: $SIZE foo=\"baz bar\" " ]
