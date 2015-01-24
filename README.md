# bakassabl
A (very) cheap Linux sandboxer based on seccomp


## Compile
```
 $ ./gen_bakassabl.h.sh > bakassabl.h
 $ cc -o bakassabl -Werror -O1 -fPIE -fPIC -fstack-protector-all -Wl,-z,relro bakassabl.c -lseccomp -pie
```


##  Examples
```
 $ ./bakassabl --verbose --paranoid  -- /bin/ping -c 10 localhost
 $ ./bakassabl --verbose --allow-all --deny connect -- /usr/bin/ncat -v4 localhost 22
 $ ./bakassabl --verbose --allow-all --deny connect -- /bin/cat /etc/passwd
 $ ./bakassabl --verbose --deny-all  --allow exit -- ./myexit
```

## ToDo
* deny-all mode is not fully operational


## Author
* @_hugsy_