sysctls
=======

The following sysctls are available for the XFS filesystem:

  fs.xfs.stats_clear		(Min: 0  Default: 0  Max: 1)
	Setting this to "1" clears accumulated XFS statistics
	in /proc/fs/xfs/stat.  It then immediately resets to "0".

  fs.xfs.xfssyncd_centisecs	(Min: 100  Default: 3000  Max: 720000)
  	The interval at which the xfssyncd thread flushes metadata
  	out to disk.  This thread will flush log activity out, and
  	do some processing on unlinked inodes.

  fs.xfs.xfsbufd_centisecs	(Min: 50  Default: 100	Max: 3000)
	The interval at which xfsbufd scans the dirty metadata buffers list.

  fs.xfs.age_buffer_centisecs	(Min: 100  Default: 1500  Max: 720000)
	The age at which xfsbufd flushes dirty metadata buffers to disk.

  fs.xfs.error_level		(Min: 0  Default: 3  Max: 11)
	A volume knob for error reporting when internal errors occur.
	This will generate detailed messages & backtraces for filesystem
	shutdowns, for example.  Current threshold values are:

		XFS_ERRLEVEL_OFF:       0
		XFS_ERRLEVEL_LOW:       1
		XFS_ERRLEVEL_HIGH:      5

  fs.xfs.panic_mask		(Min: 0  Default: 0  Max: 127)
	Causes certain error conditions to call BUG(). Value is a bitmask;
	AND together the tags which represent errors which should cause panics:

		XFS_NO_PTAG                     0
		XFS_PTAG_IFLUSH                 0x00000001
		XFS_PTAG_LOGRES                 0x00000002
		XFS_PTAG_AILDELETE              0x00000004
		XFS_PTAG_ERROR_REPORT           0x00000008
		XFS_PTAG_SHUTDOWN_CORRUPT       0x00000010
		XFS_PTAG_SHUTDOWN_IOERROR       0x00000020
		XFS_PTAG_SHUTDOWN_LOGERROR      0x00000040

	This option is intended for debugging only.

  fs.xfs.irix_symlink_mode	(Min: 0  Default: 0  Max: 1)
	Controls whether symlinks are created with mode 0777 (default)
	or whether their mode is affected by the umask (irix mode).

  fs.xfs.irix_sgid_inherit	(Min: 0  Default: 0  Max: 1)
	Controls files created in SGID directories.
	If the group ID of the new file does not match the effective group
	ID or one of the supplementary group IDs of the parent dir, the
	ISGID bit is cleared if the irix_sgid_inherit compatibility sysctl
	is set.

  fs.xfs.inherit_sync		(Min: 0  Default: 1  Max: 1)
	Setting this to "1" will cause the "sync" flag set
	by the xfs_io(8) chattr command on a directory to be
	inherited by files in that directory.

  fs.xfs.inherit_nodump		(Min: 0  Default: 1  Max: 1)
	Setting this to "1" will cause the "nodump" flag set
	by the xfs_io(8) chattr command on a directory to be
	inherited by files in that directory.

  fs.xfs.inherit_noatime	(Min: 0  Default: 1  Max: 1)
	Setting this to "1" will cause the "noatime" flag set
	by the xfs_io(8) chattr command on a directory to be
	inherited by files in that directory.

  fs.xfs.inherit_nosymlinks	(Min: 0  Default: 1  Max: 1)
	Setting this to "1" will cause the "nosymlinks" flag set
	by the xfs_io(8) chattr command on a directory to be
	inherited by files in that directory.

  fs.xfs.rotorstep		(Min: 1  Default: 1  Max: 256)
	In "inode32" allocation mode, this option determines how many
	files the allocator attempts to allocate in the same allocation
	group before moving to the next allocation group.  The intent
	is to control the rate at which the allocator moves between
	allocation groups when allocating extents for new files.
