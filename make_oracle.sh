#!/bin/bash 
uuid="2a29f520-1100-4824-b5d9-d841f1267838"

if [ "$#" -gt 1 ]; then
    echo "only one argument allowed: device to modify, e.g. /dev/nvme2n1p1"
    exit 1
fi

if [ "$#" -eq 1 ]; then
    dev=$1
    lines=$(blkid $1 | grep $uuid | wc -l)
    if [ $lines != 1 ]; then
        echo "the device $dev doesn't have the expected UUID $uuid"
        exit 1
    fi
else
    count=$(blkid | grep $uuid | wc -l)
    if [ $count == 0 ]; then
        echo "a disk with uuid $uuid was not detected"
        echo "please attach it first and rerun"
        exit 1
    fi
    if [ $count != 1 ]; then
        echo "more than one disk with uuid $uuid detected"
        echo "please specify explicitely what disk you'd like to modify, e.g:"
        echo "sudo ./make_oracle.sh /dev/nvme2n1p1"
        exit 1
    else
        dev=$(blkid --uuid $uuid)
    fi
fi

mountpoint=$(mount | grep $dev | cut -d' ' -f3)
echo $mountpoint
if [ ! -z $mountpoint ] && [ $mountpoint = "/" ]; then
    echo "will not modify $dev because it is mounted on /"
    exit 1
fi

echo "will modify device $dev"
DISK=$(mktemp -d)
mount $dev $DISK

# use our custom grub.cfg
cp grub/grub.cfg $DISK/boot/grub/grub.cfg
mkdir -p $DISK/home/ubuntu/server
cp -R server $DISK/home/ubuntu
cp -R systemd $DISK/root
cp systemd/tlsnotary_* $DISK/etc/systemd/system/
#make services start on boot
ln -s /etc/systemd/system/tlsnotary_server.service $DISK/etc/systemd/system/graphical.target.wants/
ln -s /etc/systemd/system/tlsnotary_server.path $DISK/etc/systemd/system/graphical.target.wants/
ln -s /etc/systemd/system/tlsnotary_setup.service $DISK/etc/systemd/system/graphical.target.wants/

# remove ssh logins
rm $DISK/usr/sbin/sshd
rm $DISK/etc/systemd/system/sshd.service
rm $DISK/lib/systemd/system/ssh.service
rm $DISK/etc/init.d/ssh
# remove tty logins
rm $DISK/sbin/agetty
rm $DISK/lib/systemd/system/getty@.service
rm -R $DISK/etc/systemd/system/getty.target.wants
# remove serial console logins
rm -R $DISK/lib/systemd/system/serial-getty@.service
# disable cloudinit modules through which user data can potentially be passed to the instance
sed -i 's/- bootcmd//' $DISK/etc/cloud/cloud.cfg
sed -i 's/- runcmd//' $DISK/etc/cloud/cloud.cfg
sed -i 's/- rightscale_userdata//' $DISK/etc/cloud/cloud.cfg
sed -i 's/- scripts-user//' $DISK/etc/cloud/cloud.cfg
sed -i 's/- ssh//' $DISK/etc/cloud/cloud.cfg

# unpack initrd, add our custom script and repack
tmp=$(mktemp -d)
dd if=$DISK/boot/initrd.img-5.11.0-1020-aws of=$tmp/microcode bs=512 count=9066
dd if=$DISK/boot/initrd.img-5.11.0-1020-aws of=$tmp/initrd_old bs=512 skip=9066
mkdir $tmp/cpio && (unlz4 | cpio -i -D $tmp/cpio) < $tmp/initrd_old
cp initrd/custom $tmp/cpio/scripts/init-premount/custom
echo '/scripts/init-premount/custom "$@"' >> $tmp/cpio/scripts/init-premount/ORDER
chmod +x $tmp/cpio/scripts/init-premount/custom
find $tmp/cpio -exec touch -amht 202001020304 {} +
pushd $tmp/cpio && find . | sort -t \n | cpio --reproducible -H newc -o | gzip > $tmp/initrd && popd
cat $tmp/microcode $tmp/initrd > $DISK/boot/initrd
rm -r $tmp

umount $dev
echo "$dev has been successfully modified"