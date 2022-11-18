

ltrace -c ls
ltrace -p <PID>
ltrace -l /lib/libselinux.so.1 id -Z 		#execute the id -Z command and show the calls made to the libselinux.so module
ltrace -o foobar.log ./foobar 				#edirect output of ltrace to a file
ltrace -e malloc ./foobar 					#filter and display only calls to a certain library function

