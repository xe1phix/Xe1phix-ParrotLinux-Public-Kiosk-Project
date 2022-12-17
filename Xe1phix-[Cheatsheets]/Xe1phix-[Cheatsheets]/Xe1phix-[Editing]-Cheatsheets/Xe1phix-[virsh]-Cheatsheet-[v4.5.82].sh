!/bin/sh



virsh list

virsh dumpxml VM_NAME | grep 'source file'
virsh dumpxml --domain VM_NAME | grep 'source file'

# <source file='/nfswheel/kvm/VM_NAME.qcow2'/>
virsh shutdown VM_NAME
# OR as below
# virsh destroy VM_NAME
virsh snapshot-list VM_NAME
virsh snapshot-delete VM_NAME
virsh undefine VM_NAME




virsh pool-info $pool &>/dev/null || return
path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')

qemu-nbd -d /dev/nbd0




virsh dumpxml $NAME > $NAME.xml
virsh define $NAME.xml
	
	
VNC_PORT=$(virsh vncdisplay $domain | awk -F ":" '{print $2}' | sed 's/\<[0-9]\>/0&/')
	
	
	
	
	
	
qemu-img create -f qcow2 ubuntu1204.img 10G
qemu-img convert -c ubuntu1204.img -O qcow2 ubuntu1204.qcow2
scp ubuntu1204.qcow2 root@192.168.1.145:/root

virt-install -n Win2k8r2 -r 2048 --vcpus 2 --os-type=windows --os-variant=win2k8 --disk path=/var/image/win2k8r2.img,format=qcow2,bus=virtio,cache=none --disk path=/var/lib/libvirt/images/virtio-win-drivers-20120712-1.iso,device=cdrom -w network=default,model=virtio --vnc --noautoconsole -c /home/uycn/Win2k8R2.ISO




qemu-img create -O qcow2 /media/VMs/windows.qcow2 8G
# qemu -boot d -cdrom /media/sf_VMs/winxp.iso -hda /media/VMs/windows.qcow2 -m 1024

# qemu -hda /media/VMs/windows.qcow2 -m 1024


qemu-system-x86_64 -hda /path/$File qcow2 -m 1024

# virsh snapshot-create cuckoo1 /media/sf_VMs/snap1.xml


virsh start cuckoo1
# virsh list –all



virsh snapshot-list 
 | awk '{print $1}'

virsh snapshot-create f15guest /var/tmp/snap1-f15guest.xml


virsh snapshot-create-as $i $SNAP_NAME

virsh snapshot-revert $i $SNAP_NAME

virsh resume $i



virsh pool-info $pool &>/dev/null || return
path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')


	
	
	
virsh vol-list --pool default
	
virsh pool-info $pool
path=$(virsh pool-dumpxml $pool | sed -n '/path/{s/.*<path>\(.*\)<\/path>.*/\1/;p}')
echo $path

virsh pool-define-as default dir - - - - "$path"
virsh pool-build default
virsh pool-start default
virsh pool-autostart default
	
	
virsh net-define ${NET}.xml
virsh net-autostart ${NET}
virsh net-start ${NET}
	
	
	
virsh pool-info default
virsh vol-create-as --name $name.qcow2 --capacity $size --format qcow2 --allocation $size --pool default

virt-install \
  --name=$name \
  --ram=$ram \
  --vcpus=$cpu,cores=$cpu \
  --os-type=linux \
  --os-variant=rhel6 \
  --virt-type=kvm \
  --disk "$pool_path/$name.qcow2",cache=writeback,bus=virtio,serial=$(uuidgen) \
  --cdrom "$pool_path/$iso_name" \
  --noautoconsole \
  --network network=fuel-pxe,model=$net_driver \
  --network network=$external_network,model=$net_driver \
  --graphics vnc,listen=0.0.0.0



STATUS=$(virsh dominfo $name | grep State | awk '{print $2}')
  
virsh start $name





Open Virt-Manager > click + > Bridge > br0 > Start Mode: onboot > Activate Now > Check eth0



	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	




see some information about the VM size, snapshot info:
qemu-img info /export/vmimgs/f15guest.qcow2

virsh snapshot-create-as --domain vm1 snap1 \ 
  --diskspec vda,file=/export/vmimages/disk-snap.qcow2,snapshot=external \ 
  --memspec file=/export/vmimages/mem-snap.qcow2,snapshot=external \ 
  --atomic

  
  qemu-img create -f raw <name>.img <Size>
  
  
  
  Launch VM with virt-install

    virt-install --name spinnaker \
    --ram 11096 \
    --vcpus=4 \
    --os-type linux \
    --os-variant=ubuntutrusty \
    --accelerate \
    --nographics -v  \
    --disk path=/var/lib/libvirt/images/ubuntu14-HD.img,size=8 \
    --extra-args "console=ttyS0" \
    --location /opt/ubuntu14.iso --force \
    --network bridge:virbr0
  
  
  
  
qemu-img convert -f raw -O qcow2 /var/lib/libvirt/images/ubuntu14-HD.img /home/opsmx/spinnaker.qcow2
  
  
  
qemu-img convert -O qcow2 REMnuxV6-disk1.vmdk remnux.qcow2
  
  
  
  
  
  Connect to tty of the VM (If tty is enables)
  virsh console <VM name>
  
  
  virsh dumpxml <VM name> - Dumps configuration of VM in xml format
virsh net-list - List the available networks











virsh migrate --live --verbose generic qemu+ssh://$destinationIP/system


ssh $destinationIP export LIBVIRT_DEFAULT_URI=qemu:///system
ssh  $destinationIP "export LIBVIRT_DEFAULT_URI=qemu:///system; virsh migrate --live --persistent generic qemu+ssh://$sourceIP/system"





