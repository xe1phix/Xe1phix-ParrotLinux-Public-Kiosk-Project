#how to delete file with inode
find . -inum 1847 -ls
find . -inum 1847 -exec rm {} \;

find . -inum 782263 -exec rm -i {} \;

#how to delete directory/folder with inode
find . -inum 393232 -delete
