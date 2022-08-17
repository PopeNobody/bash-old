file /bin/xbash
set remote exec-file /bin/xbash
target extended-remote localhost:9999
source breakpoints.gdb
run
