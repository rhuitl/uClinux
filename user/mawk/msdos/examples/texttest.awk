# Ben Myers <0003571400@mcimail.com>

/^#include/ {
# got #include, see if it has at least one quote. We don't want #include <>        
        z = gsub(/"/, "", $2)
        while ((z > 0) && (getline x <$2 > 0)) 
#        while (getline x <$2 > 0) 
                print x
        next
}
{ print }
