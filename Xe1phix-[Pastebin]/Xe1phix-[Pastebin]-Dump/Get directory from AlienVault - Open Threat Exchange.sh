#Save below codes in your os default shell profile and source it or restart terminal to apply changes , Ex:
#nano .bash_profile [ For bash shell ]
#nano .bashrc [ For Red Hat ]
#nano .profile [ For Ubuntu ]

otx()
{
	gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$1?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq
}

#Source !$
#otx target.com
#Make sure you have @TomNomNom gron installed or‬ install: go get -u github.com/tomnomnom/gron
#Must check on every active subdomain one by one or code a script to run it from a listed subdomain using ruby or bash .