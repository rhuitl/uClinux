#! /bin/sh

SIZE=$(echo `wc -c < tests/test-insmod/02simple.sh`)
[ "`insmod - < tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -s - < tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -f - < tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
[ "`insmod -p -f -s - < tests/test-insmod/02simple.sh`" = "INIT_MODULE: $SIZE " ]
