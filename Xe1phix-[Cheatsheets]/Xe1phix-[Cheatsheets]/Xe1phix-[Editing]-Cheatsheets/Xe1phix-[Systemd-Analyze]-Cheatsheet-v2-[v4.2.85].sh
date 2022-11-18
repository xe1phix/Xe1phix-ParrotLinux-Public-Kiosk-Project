systemd-analyze 				#the actual boot time of the machine
systemd-analyze blame 			#see how long every program and service takes to start up
systemd-analyze critical-chain 	# print out the results in a chain of events style

systemd-analyze critical-chain ntp.service networking.service


systemd-analyze plot > boot_analysis.svg
xviewer boot_analysis.svg  
systemd-analyze time -H tecmint@192.168.56.5 		#view information from a remote host over ssh
systemd-analyze blame -H tecmint@192.168.56.5


systemd-cgtop 										#top control groups by their resource usage such as tasks, CPU, Memory, Input, and Output
