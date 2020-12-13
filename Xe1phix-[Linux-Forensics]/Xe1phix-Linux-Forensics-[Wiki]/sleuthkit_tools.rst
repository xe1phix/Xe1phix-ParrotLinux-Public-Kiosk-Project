SleuthKit Tools
---------------

**File System Layer Tools (Partition Information)**

=========  ======================================  ========================
Tool Name  Description                             Example
=========  ======================================  ========================
fsstat     Displays details about the file system  ``fsstat imagefile.dd`` 
=========  ======================================  ========================

**Data Layer Tools (Block or Cluster)**

=========  ========================================  ========================================
Tool Name  Description                               Example
=========  ========================================  ========================================
blkcat     Displays the contents of a disk block     ``blkcat imagefile.dd block_num``
blkls      Lists contents of deleted disk blocks     ``blkls imagefile.dd > imagefile.blkls``
blkcalc    Maps between dd images and blkls results  ``blkcalc imagefile.dd -u blkls_num``
blkstat    Display allocation status of block        ``blkstat imagefile.dd cluster_number``
=========  ========================================  ========================================

**MetaData Layer Tools (inode, MFT, or Directory Entry)**

=========  =================================================  ========================================
Tool Name  Description                                        Example
=========  =================================================  ========================================
ils        Displays inode details                             ``ils imagefile.dd``
istat      Displays information about a specific inode        ``istat imagefile.dd inode_num``
icat       Displays contents of blocks allocated to an inode  ``icat imagefile.dd inode_num``
ifind      Determine which inode contains a specific block    ``ifind imagefile.dd –d block_num``
=========  =================================================  ========================================

**Filename Layer Tools**

=========  ==================================================  ========================================
Tool Name  Description                                         Example
=========  ==================================================  ========================================
fls        Displays deleted file entries in a directory inode
ffind      Find the filename that using the inode
=========  ==================================================  ========================================
