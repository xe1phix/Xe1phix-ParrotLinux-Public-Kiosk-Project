
virsh cheat sheet
Phil Lembo edited this page on Jan 17, 2019 · 3 revisions

created: 2013/04/21 19:24:36

Virsh is a command line utility for managing KVM (Kernel Virtual Machine) guests. This is its cheat sheet.

The material that follows comes from a post by Jaime Frutos Morales in 2010. Many thanks to Jaime for bringing this info together in such a clear and concise way. In kvm terms guests are referred to as domains, so in the examples that follow "nameofdomain" would be replaced by something like "linuxtest1".
Information

List all defined domains (guests):

virsh list --all

Show info about a domain:

virsh dominfo nameofdomain

Start and Stop

Start a guest:

virsh start nameofdomain

Shutdown:

virsh shutdown nameofdomain

Force Shutdown:

virsh destroy nameofdomain

Suspend:

virsh suspend nameofdomain

Resume:

virsh resume nameofdomain

Autostart:

virsh autostart nameofdomain

Disable autostart:

virsh autostart --disable nameofdomain

Creating and Modifying Domains

Create domain from xml file:

virsh create domainfile.xml

Dump domain definition to xml:

virsh dumpxml nameofdomain >domainfile.xml

Modify domain definition:

virsh edit nameofdomain

Remove domain definition:

virsh undefine nameofdomain

Backup and Restore

Save domain state:

virsh save nameofdomain domainfile

Restore domain from file:

virsh restore domainfile

