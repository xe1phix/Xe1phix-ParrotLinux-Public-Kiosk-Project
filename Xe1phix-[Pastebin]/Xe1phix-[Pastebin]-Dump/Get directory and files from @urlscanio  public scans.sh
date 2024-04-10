#Save below codes in your os default shell profile and source it or restart terminal to apply changes , Ex:
#nano .bash_profile [ For bash shell ]
#nano .bashrc [ For Red Hat ]
#nano .profile [ For Ubuntu ]

urlscan()
{
	gron "https://urlscan.io/api/v1/search/?q=domain:$1" | grep 'url' | gron --ungron | jq
}


#Source !$
#urlscan target.com
#Make sure you have @TomNomNom gron installed or‬ install: go get -u github.com/tomnomnom/gron