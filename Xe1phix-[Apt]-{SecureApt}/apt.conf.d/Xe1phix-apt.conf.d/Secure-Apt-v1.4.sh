#!/bin/sh
## #######
## ## 
## #######
## 




DPkg::Post-Invoke:: "/usr/bin/test -x /sbin/paxrat && /sbin/paxrat -c /etc/paxrat/paxrat.conf || true";


Dir::Etc::trusted "trusted.gpg";
Dir::Etc::trustedparts "trusted.gpg.d";
APT::Authentication::TrustCDROM "true";
APT::Sandbox::User "_apt";


TRUSTEDFILE="/etc/apt/trusted.gpg"
eval $(apt-config shell TRUSTEDFILE Apt::GPGV::TrustedKeyring)
eval $(apt-config shell TRUSTEDFILE Dir::Etc::Trusted/f)

GPG="$GPG --primary-keyring $TRUSTEDFILE"
	TRUSTEDPARTS="/etc/apt/trusted.gpg.d"
	eval $(apt-config shell TRUSTEDPARTS Dir::Etc::TrustedParts/d)
	if [ -d "$TRUSTEDPARTS" ]; then
		#echo "parts active"
		for trusted in $(run-parts --list $TRUSTEDPARTS --regex '^.*\.gpg$'); do
			#echo "part -> $trusted"
			GPG="$GPG --keyring $trusted"
		done
	fi

eval $(apt-config shell TRUSTDBDIR Dir::Etc/d)
GPG_CMD="$GPG_CMD --trustdb-name ${TRUSTDBDIR}/trustdb.gpg"








Dpkg::Checksums
Dpkg::Compression
Dpkg::Compression::FileHandle
Dpkg::Compression::Process
Dpkg::Control::Fields
Dpkg::Control::FieldsCore
Dpkg::Control::Hash
Dpkg::Control::HashCore
Dpkg::Control::Info
Dpkg::Build::Env
Dpkg::BuildFlags
Dpkg::Build::Info
Dpkg::BuildOptions
Dpkg::BuildProfiles
Dpkg::Build::Types


Aptitude::Logging::File
Aptitude::Logging::Levels
Aptitude::Always-Use-Safe-Resolver true
Aptitude::CmdLine::Show-Summary
Aptitude::CmdLine::Verbose
Aptitude::Log  /var/log/aptitude
Aptitude::Logging::File /var/log/aptitude/apt.log
Aptitude::Logging::Levels


echo "Configuration fragment files:"
/etc/dpkg/dpkg.cfg.d/[0-9a-zA-Z_-]*

echo "Configuration file with default options.:"
/etc/dpkg/dpkg.cfg
/var/cache/apt/archives
/etc/cron.daily/apt					# 
echo "Default log file:"
/var/log/dpkg.log
/var/lib/apt/lists/
/usr/share/doc/apt/examples/configure-index.gz
/etc/apt/apt.conf.d/
/etc/apt/apt.conf
/var/lib/apt/lists
/etc/apt/trusted.gpg			# Keyring of local trusted keys, new keys will be added here
/etc/apt/trustdb.gpg			# Local trust database of archive keys.
/etc/apt/trusted.gpg.d/			# File fragments for the trusted keys, additional keyrings can be
/usr/share/keyrings/debian-archive-keyring.gpg			# Keyring of Debian archive trusted keys.
/usr/share/keyrings/debian-archive-removed-keys.gpg		# Keyring of Debian archive removed trusted keys.
/usr/share/debconf/templates/
/var/lib/apt/cdroms.list
echo " Locations to fetchPackages from:"
/etc/apt/sources.list.d/			# File fragments for locations to fetchPackages from. 
/var/lib/apt/lists/					# information for eachPackage resource specified in sources.list(5) 
/var/lib/apt/lists/partial/			# Storage area for state information in transit. 
~/.aptitude/config
/var/lib/aptitude/pkgstates
/usr/share/doc/aptitude/html/<lang>/index.html

echo "change locations of these files.:"
--admindir
echo "List of availablePackages:"
cat /var/lib/dpkg/available

echo "Statuses of availablePackages:"
cat /var/lib/dpkg/status
echo "ListPackages matching given pattern:"

echo "Report status of specifiedPackage.:"
--status 
echo "List files installed to your system fromPackage-name.:"
--listfiles 
echo "Search for a filename from installedPackages.:"
--search 
echo "Display details aboutPackage-name, as found in /var/lib/dpkg/available. :"
--print-availPackage-name...



echo "Users of APT-based frontends should use apt-cache showPackage-name instead.:"


echo "let dpkg-source create a debian.tar.bz2 with maximal compression
compression = "bzip2"
compression-level = 9
echo "use debian/patches/debian-changes as automatic patch
single-debian-patch
echo "ignore changes on config.{sub,guess}
extend-diff-ignore = "(^|/)(config.sub|config.guess)$"


To make a local copy of thePackage selection states:
dpkg --get-selections >myselections


avail=`mktemp`
apt-cache dumpavail >"$avail"
dpkg --merge-avail "$avail"
rm "$avail"
 you can install it with:
dpkg --clear-selections
dpkg --set-selections <myselections
apt-get dselect-upgrade



dpkg.cfg
dpkg-reconfigure

apt-cache showpkg 
apt.conf
VCG tool[2]



apt-extracttemplates


aide.wrapper



cowpoke
cvs-debc



/usr/share/doc/apt/examples/configure-index.gz
/usr/share/doc/apt/examples/apt.conf
/usr/share/doc/apt/examples/configure-index.gz

/usr/bin/fakeroot-sysv
/usr/bin/fakeroot-tcp
/usr/bin/fakeroot

APT_CONFIG
/usr/share/debconf/templates/
Acquire::cdrom::mount
/var/lib/usbutils/usb.ids
/usr/share/dpkg

Debug::pkgAcquire::Auth
Debug::Hashes
Debug::aptcdrom
Debug::Acquire::gpgv
Debug::Acquire::cdrom

Debug::Acquire::ftp
Debug::Acquire::http
Debug::Acquire::https
dpkg-buildpackage

dpkg --configure --pending


--verify 
--verify-format deb
--audit 
--validate-pkgname

--clear-avail

--get-selections 
--debug=help

dpkg-deb 

--contents  			## List contents of a deb package.
--info  				## Show information about a package.
--control   			## Extract control-information from a package
--vextract   				## Extract and display the filenames contained by a package.
--field  archive  			## Display control field(s) of a package


dpkg-query 




apt-config shell MaxAge APT::Archives::MaxAge)
apt-config shell MaxAge APT::Periodic::MaxAge)

apt-config shell MinAge APT::Archives::MinAge)
apt-config shell MinAge APT::Periodic::MinAge)

apt-config shell MaxSize APT::Archives::MaxSize)
apt-config shell MaxSize APT::Periodic::MaxSize)

Cache="/var/cache/apt/archives/"
apt-config shell Cache Dir::Cache::archives/d)

Apt::Periodic::BackupArchiveInterval

CacheDir="/var/cache/apt"
apt-config shell CacheDir Dir::Cache/d

BackupLevel=3
apt-config shell BackupLevel APT::Periodic::BackupLevel

Back="${CacheDir}/backup/"
apt-config shell Back Dir::Cache::Backup/d

BACKUP_ARCHIVE_STAMP=/var/lib/apt/periodic/backup-archive-stamp


apt-config shell VERBOSE APT::Periodic::Verbose





APT_HOOK_INFO_FD
DPkg::Tools::options::cmd::InfoFD


AllowInsecureRepositories false
EnableSrvRecords true
ForceIPv4 

Acquire::Languages { "environment"; "de"; "en"; "none"; "fr"; };
Acquire::Languages=none													## Note: To prevent problems resulting from APT being executed in different environment

Acquire::CompressionTypes::Order:: "gz";
Acquire::CompressionTypes::Order { "xz"; "gz"; };


gpgv::Options,
AllowTLS



Acquire::ftp


https




Create a toplevel Release file

apt-ftparchive release

gpg --clearsign -o InRelease Release 
gpg -abs -o Release.gpg Release

debsig-verify
debsign
debian-keyring
debian-archive-keyring

apt-transport-tor
apt-transport-https



apt_auth.conf

deb [ option1=value1 option2=value2 ] uri suite [component1] [component2] [...]
deb-src [ option1=value1 option2=value2 ] uri suite [component1] [component2] [...]


Types: deb deb-src
URIs: uri
Suites: suite
Components: [component1] [component2] [...]
option1: value1
option2: value2


           deb http://deb.debian.org/debian stretch main contrib non-free
           deb http://security.debian.org stretch/updates main contrib non-free

       or like this in deb822 style format:

           Types: deb
           URIs: http://deb.debian.org/debian
           Suites: stretch
           Components: main contrib non-free

           Types: deb
           URIs: http://security.debian.org
           Suites: stretch/updates
           Components: main contrib non-free

           deb http://deb.debian.org/debian stable main contrib
           deb-src http://deb.debian.org/debian stable main contrib
           deb http://deb.debian.org/debian testing main contrib
           deb-src http://deb.debian.org/debian testing main contrib
           deb http://deb.debian.org/debian unstable main contrib
           deb-src http://deb.debian.org/debian unstable main contrib

           Types: deb deb-src
           URIs: http://deb.debian.org/debian
           Suites: stable testing unstable
           Components: main contrib


APT::Default-Release "stable";
APT::Architectures


/cdrom/::Mount "/dev/sr0";
/var/lib/apt/cdroms.list
Acquire::cdrom::AutoDetect 

apt-cdrom --cdrom
Acquire::cdrom::mount.

 --config-file /etc/apt/*/apt.conf


--option 
-o Foo::Bar=bar -o 

-o Debug::Acquire::gpgv=








APT::ExtractTemplates::TempDir

Dir::Etc::Trusted /etc/apt/trusted.gpg
Dir::Etc::TrustedParts /etc/apt/trusted.gpg.d/


adv --recv-key

list
export
exportall
gpg --armor --export


apt-key --keyring /etc/apt/trusted.gpg 

showinstall 
showremove
showpurge

Acquire::http::Proxy-Auto-Detect
Acquire::http::Proxy::host.

squid-deb-proxy-client
auto-apt-proxy


Acquire::http::User-Agent 


Acquire::http::SendAccept


           Acquire::http {
                Proxy::example.org "DIRECT";
                Proxy "socks5h://apt:pass@localhost:9050";
                Proxy-Auto-Detect "/usr/local/bin/apt-http-proxy-auto-detect";
                No-Cache "true";
                Max-Age "3600";
                No-Store "true";
                Timeout "10";
                Dl-Limit "42";
                Pipeline-Depth "0";
                AllowRedirect "false";
                User-Agent "My APT-HTTP";
                SendAccept "false";
           };





DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt";};


dpkg::pre-install-pkgs 


Dir::State::status
/var/lib/dpkg/status,


Dir::Bin::Methods gzip,bzip2, lzma, dpkg, apt-get dpkg-source dpkg-buildpackage and apt-cache



            // Pre-configure all packages before
            // they are installed.
            DPkg::Pre-Install-Pkgs {
                   "dpkg-preconfigure --apt --priority=low";
            };










AllowInsecureRepositories false
AllowWeakRepositories false
AllowDowngradeToInsecureRepositories false
EnableSrvRecords true
ForceIPv4

gpgv::Options





/var/lib/apt/cdroms.list
echo " Locations to fetchPackages from:"
/etc/apt/sources.list.d/			# File fragments for locations to fetchPackages from. 
/var/lib/apt/lists/					# information for eachPackage resource specified in sources.list(5) 
/var/lib/apt/lists/partial/			# Storage area for state information in transit. 


Item: APT::ExtractTemplates::TempDir			# Temporary directory in which to write extracted debconf template files and config scripts


Acquire::cdrom::mount
Item: Dir::State::Lists
Dir::Etc::SourceParts
Dir::Etc::SourceList
Aptitude::Always-Use-Safe-Resolver
Aptitude::Safe-Resolver::No-New-Upgrades
Aptitude::CmdLine::Show-Deps
Aptitude::CmdLine::Download-Only
Aptitude::CmdLine::Package-Display-Format
Aptitude::CmdLine::Version-Display-Format.
Aptitude::CmdLine::Versions-Group-By.
Aptitude::Logging::File
Aptitude::Logging::Levels.
Aptitude::Log=/tmp/my-log
Aptitude::CmdLine::Always-Prompt.
Aptitude::CmdLine::Show-Size-Changes.
Aptitude::CmdLine::Show-Why
Aptitude::CmdLine::Verbose,
Aptitude::CmdLine::Show-Versions.
APT::Default-Release.
Aptitude::CmdLine::Show-Summary.	
Aptitude::Safe-Resolver::Show-Resolver-Actions.
Aptitude::CmdLine::Versions-Show-Package-Names.
Aptitude::Simulate.
Apt::Install-Recommends
Apt::AutoRemove::InstallRecommends.

APT::Periodic::Update-Package-Lists
APT::Periodic::Download-Upgradeable-Packages
APT::Periodic::AutocleanInterval
APT::Periodic::Unattended-Upgrade

APT::FTPArchive::LongDescription			# 
APT::FTPArchive::Release::Origin			# Origin, Label, Suite, Version, Codename, Date, Valid-Until, Architectures, Components, Description
APT::FTPArchive::Release::Patterns			# MD5, SHA1 and SHA256 digest for each file
APT::FTPArchive::Release::Default-Patterns			# 
APT::FTPArchive::Release
Packages::Compress			# '.' (no compression), 'gzip' and 'bzip2'
Packages::Extensions			# Sets the default list of file extensions that are package files. This defaults to '.deb'
Translation::Compress







Acquire::https {
                Proxy::example.org "DIRECT";
                Proxy "socks5h://apt:pass@localhost:9050";
                Proxy-Auto-Detect "/usr/local/bin/apt-https-proxy-auto-detect";
                No-Cache "true";
                Max-Age "3600";
                No-Store "true";
                Timeout "10";
                Dl-Limit "42";
                Pipeline-Depth "0";
                AllowRedirect "false";
                User-Agent "My APT-HTTPS";
                SendAccept "false";

                CAInfo "/path/to/ca/certs.pem";
                CRLFile "/path/to/all/crl.pem";
                Verify-Peer "true";
                Verify-Host::broken.example.org "false";
                SSLCert::example.org "/path/to/client/cert.pem";
                SSLKey::example.org "/path/to/client/key.pem"
           };


 An alternative certificate authority (CA) can be configured
Acquire::https::CAInfo
Acquire::https::CAInfo::host		## host-specific option

Acquire::https::CRLFile::host

Acquire::https::CRLFile
Acquire::https::CRLFile::host 


Acquire::https::Verify-Peer 
Acquire::https::Verify-Host

Acquire::https::SSLCert
Acquire::https::SSLKey


// Verify peer certificate and also matching between certificate name
// and server name as provided in sources.list (default values)
Acquire::https::Verify-Peer "true";
Acquire::https::Verify-Host "true";

// Except otherwise specified, use that list of anchors
Acquire::https::CaInfo     "/etc/ssl/certs/ca-certificates.pem";

// Use a specific anchor and associated CRL. Enforce issuer of
// server certificate using its cert.
Acquire::https::secure.dom1.tld::CaInfo     "/etc/apt/certs/ca-dom1-crt.pem";
Acquire::https::secure.dom1.tld::CrlFile    "/etc/apt/certs/ca-dom1-crl.pem";
Acquire::https::secure.dom1.tld::IssuerCert "/etc/apt/certs/secure.dom1-issuer-crt.pem";

// Like previous for anchor and CRL, but also provide our
// certificate and keys for client authentication.
Acquire::https::secure.dom2.tld::CaInfo  "/etc/apt/certs/ca-dom2-crt.pem";
Acquire::https::secure.dom2.tld::CrlFile "/etc/apt/certs/ca-dom2-crl.pem";
Acquire::https::secure.dom2.tld::SslCert "/etc/apt/certs/my-crt.pem";
Acquire::https::secure.dom2.tld::SslKey  "/etc/apt/certs/my-key.pem";

// No need to downgrade, TLS will be proposed by default. Uncomment
// to have SSLv3 proposed.
// Acquire::https::mirror.ipv6.ssi.corp::SslForceVersion "SSLv3";

// No need for more debug if every is fine (default). Uncomment
// me to get additional information.
// Debug::Acquire::https "true";


#############################################################################################
#############################################################################################
#############################################################################################

/*
  Options with extended comments:

  Acquire::https[::repo.domain.tld]::CaInfo  "/path/to/ca/certs.pem";

    A string providing the path of a file containing the list of trusted
    CA certificates used to verify the server certificate. The pointed
    file is made of the concatenation of the CA certificates (in
    PEM format) creating the chain used for the verification of the path
    from the root (self signed one). If the remote server provides the
    whole chain during the exchange, the file need only contain the root
    certificate. Otherwise, the whole chain is required.

    If you need to support multiple authorities, the only way is to
    concatenate everything.

    If None is provided, the default CA bundle used by GnuTLS (apt https
    method is linked against libcurl-gnutls) is used. At the time of
    writing, /etc/ssl/certs/ca-certificates.crt.

    If no specific hostname is provided, the file is used by default
    for all https targets. If a specific mirror is provided, it is
    used for the https entries in the sources.list file that use that
    repository (with the same name).

  Acquire::https[::repo.domain.tld]::CrlFile  "/path/to/all/crl.pem";

    Like previous knob but for passing the list of CRL files (in PEM
    format) to be used to verify revocation status. Again, if the
    option is defined with no specific mirror (probably makes little
    sense), this CRL information is used for all defined https entries
    in sources.list file. In a mirror specific context, it only applies
    to that mirror.

  Acquire::https[::repo.domain.tld]::IssuerCert "/path/to/issuer/cert.pem";

    Allows to constrain the issuer of the server certificate (for all
    https mirrors or a specific one) to a specific issuer. If the
    server certificate has not been issued by this certificate,
    connection fails.

  Acquire::https[::repo.domain.tld]::Verify-Peer "true";

    When authenticating the server, if the certificate verification fails
    for some reason (expired, revoked, man in the middle, lack of anchor,
    ...), the connection fails. This is obviously what you want in all
    cases and what the default value (true) of this option provides.

    If you know EXACTLY what you are doing, setting this option to "false"
    allow you to skip peer certificate verification and make the exchange
    succeed. Again, this option is for debugging or testing purpose only.
    It removes ALL the security provided by the use of SSL.TLS to secure
    the HTTP exchanges.

  Acquire::https[::repo.domain.tld]::Verify-Host "true";

    The certificate provided by the server during the TLS/SSL exchange
    provides the identity of the server which should match the DNS name
    used to access it. By default, as requested by RFC 2818, the name
    of the mirror is checked against the identity found in the
    certificate. This default behavior is safe and should not be
    changed. If you know that the server you are using has a DNS name
    which does not match the identity in its certificate, you can
    [report that issue to its administrator or] set the option to
    "false", which will prevent the comparison to be done.

    The options can be set globally or on a per-mirror basis. If set
    globally, the DNS name used is the one found in the sources.list
    file in the https URI.

  Acquire::https[::repo.domain.tld]::SslCert "/path/to/client/cert.pem";
  Acquire::https[::repo.domain.tld]::SslKey  "/path/to/client/key.pem";

    These two options provides support for client authentication using
    certificates. They respectively accept the X.509 client certificate
    in PEM format and the associated client key in PEM format (non
    encrypted form).

    The options can be set globally (which rarely makes sense) or on a
    per-mirror basis.

  Acquire::https[::repo.domain.tld]::SslForceVersion "TLSv1";

    This option can be use to select the version which will be proposed
    to the server. "SSLv3" and "TLSv1" are supported. SSLv2, which is
    considered insecure anyway is not supported (by gnutls, which is
    used by libcurl against which apt https method is linked).

    When the option is set to "SSLv3" to have apt propose SSLv3 (and
    associated sets of ciphersuites) instead of TLSv1 (the default)
    when performing the exchange. This prevents the server to select
    TLSv1 and use associated ciphersuites. You should probably not use
    this option except if you know exactly what you are doing.

    Note that the default setting does not guarantee that the server
    will not select SSLv3 (for ciphersuites and SSL/TLS version as
    selection is always done by the server, in the end). It only means
    that apt will not advertise TLS support.

  Debug::Acquire::https "true";

    This option can be used to show debug information. Because it is
    quite verbose, it is mainly useful to debug problems in case of
    failure to connect to a server for some reason. The default value
    is "false".

*
#############################################################################################
#############################################################################################
#############################################################################################















--log-file=/var/log/aptitude
--log-level=fatal, error, warn, info, debug, and trace
--log-level=aptitude.resolver:fatal
--log-level=aptitude.resolver.hints.match:trace,
aptitude.resolver.hints.parse
aptitude.resolver.hints.match
--log-resolver
--log-level=aptitude.resolver.search:trace
--log-level=aptitude.resolver.search.tiers:info.
--show-resolver-actions.
--autoclean-on-startup
aptitude -v --show-summary=all-packages-with-dep-versions
aptitude -v --show-summary=first-package-and-type


apt-cdrom add -d /media/cdrom/
  -a   Thorough scan mode



apt.conf(5), sources.list(5), apt-get
gencaches			# Build both thePackage and source cache
showpkg			# Show some general information for a singlePackage
showsrc			# Show source records
stats			# Show some basic statistics
dump			# Show the entire file in a terse form
dumpavail						# Print an available file to stdout
unmet			# Show unmet dependencies
search			# Search thePackage list for a regex pattern
show			# Show a readable record for thePackage
depends			# Show raw dependency information for aPackage
rdepends			# Show reverse dependency information for aPackage
pkgnames			# List the names of allPackages in the system
dotty			# GeneratePackage graphs for GraphViz
xvcg			# GeneratePackage graphs for xvcg
policy			# Show policy settings

Options:
-p=			# ThePackage cache.
-s=			# The source cache.
-q			# Disable progress indicator.
-i			# Show only important deps for the unmet command.
-c=			# Read this configuration file
-o=			# Set an arbitrary configuration option, eg -o dir::cache=/tmp




Acquire::cdrom::mount

apt-config -o dir::cache=/tmp
sources.list
apt-cdrom -d=/mnt/Parrot -o dir::cache=/mnt/Parrot
apt-cdrom -d=/mnt/poo/os/Parrot-full-2.0.5_amd64.iso -o dir::cache=/mnt/Parrot ident
ident
--cdrom			# specify the location to mount the CD-ROM
			# 
			# 
/var/lib/apt/cdroms.list

--rename			# change the label of a disc or override the disc's given label
--thorough			# ThoroughPackage Scan
--config-file
--option
--just-print,
apt-transport-https


Acquire::http::AllowRedirect
Acquire::http::Pipeline-Depth
Acquire::http::Dl-Limit
Acquire::http::User-Agent





Dir::Etc::TrustedParts
Item: Dir::Etc::Trusted


copy
trusted=yes
APT::Architectures
apt-transport-method
apt-secure
apt_preferences
Dir::State::Lists
Dir::Etc::Preferences.


DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};
DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt";};
APT::Architectures
Dir::State::Lists		# Storage area for state information in transit. 
dpkg::pre-install-pkgs
Acquire::cdrom::mount
Dir::Etc::Trusted			# File fragments for the trusted keys
Dir::Etc::TrustedParts		# Keyring of local trusted keys, new keys will be added here
APT::CDROM::Rename
APT::CDROM::NoMount
APT::CDROM::Fast
APT::CDROM::NoAct
cdrom::Mount
/cdrom/::Mount "foo";
Debug::IdentCdrom
File::Scan::ClamAV
sudo mount --bind /dev/sr0 /media/cdrom/ 




-o Foo::Bar=bar


http::Proxy
http://[[user][:pass]@]host[:port]/
http::Proxy::<host>
Acquire::http::Pipeline-Depth
Acquire::http::AllowRedirect
Acquire::http::User-Agent
<host>::CaInfo
<host>::Verify-Peer
<host>::Verify-Host
<host>::SslCert
<host>::SslKey
<host>::SslForceVersion TLSv1
<host>::SslForceVersion SSLv3
ftp::Proxy
ftp://[[user][:pass]@]host[:port]/
ftp::Proxy::<host>
$(PROXY_USER)
$(PROXY_PASS)
$(SITE_USER)
$(SITE_PASS)
$(SITE)
$(SITE_PORT)
ForceExtended



gpgv::Options

Acquire::CompressionTypes::FileExtension "Methodname";
Acquire::CompressionTypes::Order:: "gz";
Acquire::CompressionTypes::Order { "lzma"; "gz"; };
Dir::Bin::Methodname
Dir::Bin::bzip2 "/bin/bzip2";
GzipIndexes
Dir::State
Dir::Cache
Dir::Cache::archives
Dir::Etc
Dir::Parts			# reads in all the config fragments in lexical order from the directory specified.
Dir::Bin
Dir::Bin::Methods			# the method handlers and gzip, bzip2, lzma, dpkg, apt-get dpkg-source dpkg-buildpackage and
								apt-cache specify the location of the respective programs.
Dir::State::status					# 
DPkg::Tools::options::cmd::Version 2			# 
DPkg::NoTriggers "true";				# 
PackageManager::Configure "smart";		# The "smart" way is to configure onlyPackages which need 
											to be configured before anotherPackage can be unpacked 
											(Pre-Depends), and let the rest be configured by dpkg
DPkg::ConfigurePending "true";			# 


Dpkg::Control::Hash (3) - parse and manipulate a block of RFC822-like fields
Dpkg::Control::HashCore (3) - parse and manipulate a block of RFC822-like fields
Dpkg::Control::Info (3) - parse files like debian/control
Dpkg::Control::Types (3) - export CTRL_* constants
Dpkg::Deps (3)       - parse and manipulate dependencies of Debian packages
Dpkg::Conf (3)       - parse dpkg configuration files
Dpkg::Control (3)    - parse and manipulate official control-like information
Dpkg::Interface::Storable (3) - common methods related to object serialization
Dpkg::IPC (3)        - helper functions for IPC
Dpkg::Path (3)       - some common path handling functions
Dpkg::Source::Package (3) - manipulate Debian source packages
Dpkg::Substvars (3)  - handle variable substitution in strings
Dpkg::Vendor (3)     - get access to some vendor specific information
Dpkg::Vendor::Debian (3) - Debian vendor object
Dpkg::Vendor::Default (3) - default vendor object


se_dpkg (8)          - run a Debian package system programs in the proper security context
se_dpkg-reconfigure (8) - run a Debian package system programs in the proper security context


debpkg (1)           - wrapper for dpkg
dh_makeshlibs (1)    - automatically create shlibs file and call dpkg-gensymbols

dpkg-gencontrol (1)  - generate Debian control files
dpkg-gensymbols (1)  - generate symbols files (shared library dependency information)
dpkg-maintscript-helper (1) - works around known dpkg limitations in maintainer scripts
dpkg-query (1)       - a tool to query the dpkg database
dpkg-reconfigure (8) - reconfigure an already installed package
dpkg-scanpackages (1) - create Packages index files
dpkg-scansources (1) - create Sources index files
dpkg-shlibdeps (1)   - generate shared library substvar dependencies
dpkg-source (1)      - Debian source package (.dsc) manipulation tool
dpkg-split (1)       - Debian package archive split/join tool
dpkg-statoverride (1) - override ownership and mode of files
dpkg-trigger (1)     - a package trigger utility


dpkg.cfg (5)         - dpkg configuration file
Dpkg::BuildEnv (3)   - track build environment
Dpkg::BuildFlags (3) - query build flags
Dpkg::BuildOptions (3) - parse and update build options
Dpkg::BuildProfiles (3) - handle build profiles


Dpkg::Checksums (3)  - generate and manipulate file checksums
Dpkg::Compression (3) - simple database of available compression methods
Dpkg::Compression::FileHandle (3) - object dealing transparently with file compression
Dpkg::Compression::Process (3) - run compression/decompression processes
Dpkg::Conf (3)       - parse dpkg configuration files
Dpkg::Control (3)    - parse and manipulate official control-like information
Dpkg::Control::Changelog (3) - represent info fields output by dpkg-parsechangelog
Dpkg::Control::Fields (3) - manage (list of official) control fields


Dpkg::Control::FieldsCore (3) - manage (list of official) control fields
Dpkg::Control::Hash (3) - parse and manipulate a block of RFC822-like fields
Dpkg::Control::HashCore (3) - parse and manipulate a block of RFC822-like fields
Dpkg::Control::Info (3) - parse files like debian/control
Dpkg::Control::Types (3) - export CTRL_* constants



dpkg-buildflags (1)  - returns build flags to use during package build
dpkg-buildpackage (1) - build binary or source packages from sources
dpkg-checkbuilddeps (1) - check build dependencies and conflicts
dpkg-deb (1)         - Debian package archive (.deb) manipulation tool
dpkg-depcheck (1)    - determine packages used to execute a command
dpkg-distaddfile (1) - add entries to debian/files




DPkg::TriggersPending "true";			# 
DPkg::ConfigurePending					# 
PackageManager::Configure				# 
OrderList::Score::Immediate				# 
DPkg::TriggersPending					# 







designate-mdns - OpenStack DNS as a Service - mdns
designate-pool-manager - OpenStack DNS as a Service - pool manager
designate-zone-manager - OpenStack DNS as a Service - zone manager


designate - OpenStack DNS as a Service - metapackage
designate-agent - OpenStack DNS as a Service - agent
designate-api - OpenStack DNS as a Service - API server
designate-central - OpenStack DNS as a Service - central daemon
designate-common - OpenStack DNS as a Service - common files
designate-doc - OpenStack DNS as a Service - doc
designate-sink - OpenStack DNS as a Service - sink

dnssec-tools - DNSSEC tools, applications and wrappers

dnssec-trigger - reconfiguration tool to make DNSSEC work
dnstop - console tool to analyze DNS traffic
dnstracer - trace DNS queries to the source
unbound - validating, recursive, caching DNS resolver
unbound-anchor - utility to securely fetch the root DNS trust anchor
validns - high performance DNS/DNSSEC zone validator
zonecheck - DNS configuration checker
zonecheck-cgi - DNS configuration checker (web interface)


hash-slinger - tools to generate special DNS records
nslint - Lint for DNS files, checks integrity


apt-extracttemplates (1) - Utility to extract debconf config and templates from Debian packages


cowpoke (1)          - Build a Debian source package in a remote cowbuilder instance
dcontrol (1)         - - Query package and source control files for all Debian distributions
dcut (1)             - Debian archive .commands file upload tool
dd-list (1)          - nicely list .deb packages and their maintainers
deb (5)              - Debian binary package format
deb-control (5)      - Debian packages' master control file format
deb-origin (5)       - Vendor-specific information files
deb-src-control (5)  - Debian source packages' master control file format
deb-symbols (5)      - Debian's extended shared library information file
deb-systemd-helper (1p) - subset of systemctl for machines not running systemd
deb-systemd-invoke (1p) - wrapper around systemctl, respecting policy-rc.d
deb-triggers (5)     - package triggers
debc (1)             - view contents of a generated Debian package
debconf-apt-progress (1) - install packages using debconf to display a progress bar
debconf-communicate (1) - communicate with debconf
debconf-copydb (1)   - copy a debconf database
debconf-get-selections (1) - output contents of debconf database
debconf-loadtemplate (1) - load template file into debconf database
debconf-mergetemplate (1) - merge together multiple debconf template files
debconf-set-selections (1) - insert new values into the debconf database
debconf-show (1)     - query the debconf database
debconf-updatepo (1) - update PO files about debconf templates
debdiff (1)          - compare file lists in two Debian packages
debget (1)           - Fetch a .deb for a package in APT's database
debhelper (7)        - the debhelper tool suite
debi (1)             - install current version of generated Debian package


dh_builddeb (1)      - build Debian binary packages
dh_installdeb (1)    - install files into the DEBIAN directory
dh_installdebconf (1) - install files used by debconf in package build directories
dh_installmenu (1)   - install Debian menu files into package build directories
dh_listpackages (1)  - list binary packages debhelper will act on
dh_md5sums (1)       - generate DEBIAN/md5sums file

dpkg-gencontrol (1)  - generate Debian control files
dpkg-source
dpkg-split

dscextract (1)       - extract a single file from a Debian source package
dscverify (1)        - verify the validity of a Debian package
dselect (1)          - Debian package management frontend
dwarfdump (1)        - dumps DWARF debug information of an ELF object


gdebi (1)            - Simple tool to install deb files
gdebi-gtk (1)        - Simple tool to install deb files
getbuildlog (1)      - download build logs from Debian auto-builders
getipnodebyaddr (3)  - get network hostnames and addresses
getipnodebyname (3)  - get network hostnames and addresses


grep-aptavail (1)    - grep Debian control files
grep-available (1)   - grep Debian control files
grep-dctrl (1)       - grep Debian control files
grep-debtags (1)     - grep Debian control files
grep-status (1)      - grep Debian control files
grub-fstest (1)      - debug tool for GRUB filesystem drivers


make-ssl-cert (8)    - Debconf wrapper for openssl
malloc_hook (3)      - malloc debugging variables
menufile (5)         - entry in the Debian menu system

pdebuild (1)         - pbuilder way of doing debuild
qemu-make-debian-root (8) - Create a debian root image for qemu


r2 (1)               - Advanced commandline hexadecimal editor, disassembler and debugger
radare2 (1)          - Advanced commandline hexadecimal editor, disassembler and debugger



lintian

syslog-ng-ctl (1)    - Display message statistics and enable verbose, debug and trace modes in syslog-ng Open Source E...

se_apt-get (8)       - run a Debian package system programs in the proper security context
se_aptitude (8)      - run a Debian package system programs in the proper security context
se_dpkg (8)          - run a Debian package system programs in the proper security context
se_dpkg-reconfigure (8) - run a Debian package system programs in the proper security context
se_dselect (8)       - run a Debian package system programs in the proper security context
se_synaptic (8)      - run a Debian package system programs in the proper security context




dget
devscripts
debuild (1)          - build a Debian package
debuild-pbuilder (1) - A "debuild" wrapper to satisfy build-dependency before debuild


rdebsums (1)         - a recursive debsums

debsums (1)          - check the MD5 sums of installed Debian packages
debsums_init (8)     - Initialize md5sums files for packages lacking them
debtags (1)          - Command line interface to access and manipulate Debian Package Tags

debsign
debootstrap
debget

APT::Periodic							# 
APT::Archives							# 
APT::Cache::ShowFull
Debug::pkgProblemResolver			# enables output about the decisions made by dist-upgrade, upgrade, install, remove, purge.
Debug::NoLocking			# disables all file locking.
Debug::pkgDPkgPM			# prints out the actual command line each time that apt invokes dpkg
			# disables the inclusion of statfs data in CD-ROM IDs.
Acquire::Languages { "environment"; "de"; "en"; "none"; "fr"; };
Dir::Etc::Main
Dir::Etc::Parts
Explanation:.			# This provides a place for comments.
Dir::State::Lists

Contents::Header			# Sets header file to prepend to the contents output
					# Sets the output Sources file. Defaults to $(DIST)/$(SECTION)/source/Sources
Packages			# Sets the output Packages file. Defaults to $(DIST)/$(SECTION)/binary-$(ARCH)/Packages
SrcDirectory			# Sets the top of the source package directory tree. Defaults to $(DIST)/$(SECTION)/source/	
Directory			# Sets the top of the .deb directory tree. Defaults to $(DIST)/$(SECTION)/binary-$(ARCH)/
TreeDefault Section			# $(DIST), $(SECTION) and $(ARCH) replaced with their respective values
FileMode			# Specifies the mode of all created index files. It defaults to 0644.
Contents::Compress			# controls the compression for the Contents files.
			# 
			# 
			# 
			# BinCacheDB
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 
			# 





			# 
			# 

file://
cdrom://
yum repolist
mount | grep iso9660
yum list installed | grep createrepo
yum install createrepo
rpm -hiv /media/RHEL_6.4\ x86_64\ Disc\ 1/Packages/deltarpm-*
# rpm -hiv /media/RHEL_6.4\ x86_64\ Disc\ 1/Packages/python-deltarpm-*
rpm -hiv /media/RHEL_6.4\ x86_64\ Disc\ 1/Packages/createrepo-*
yum list installed | grep createrepo
mkdir /rhel_repo
cp /media/RHEL_6.4\ x86_64\ Disc\ 1/Packages/* /rhel_repo/
createrepo /rhel_repo/
pluma /etc/yum.repos.d/rhel_repo.rep

[rhel_repo]
name=RHEL_6.4_x86_64_Local
baseurl="file:///rhel_repo/"
gpgcheck=0

yum repolist


dpkg-scanpackages --multiversion . > "dists/${dist}/main/binary-amd64/Packages"
            gzip -9c "dists/${dist}/main/binary-amd64/Packages" > "dists/${dist}/main/binary-amd64/Packages.gz"
            cat > "dists/${dist}/Release"

info "Calculating sha1 for ${package}"
            calc_sha1 "${dist}" "main/binary-amd64/Packages" >> "dists/${dist}/Release"
            calc_sha1 "${dist}" "main/binary-amd64/Packages" >> "dists/${dist}/Release.gz"

APT_GET_OPTIONS="-o Dpkg::Options::="--force-confnew" --yes"
LOCAL_REPO_DIR="repo/${DIST}"



installLocalRepo() {
    local dist="${1}"

    if elementIn "$dist" ${DISTS_DEBIAN[@]}; then
        info "Adding local ${LOCAL_REPO_DIR} repo to /etc/apt/sources.list.d/local-repo.list"
        cat > "/etc/apt/sources.list.d/local-repo.list" <<EOF
deb [trusted=yes] file:$(readlink -m ${LOCAL_REPO_DIR}) ${DIST} main



Using repo= options, you can identify software repository locations. The following
examples show the syntax to use for creating repo= entries:
$ repo=hd:/dev/sda1:/myrepo

Repository in /myrepo on disk 1 first partition
$ repo=http://abc.example.com/myrepo

Repository available from /myrepo on Web server.
$ repo=ftp://ftp.example.com/myrepo

Repository available from /myrepo on FTP server.
$ repo=cdrom

Repository available from local CD or DVD
$ repo=nfs::mynfs.example.com:/myrepo/

Repository available from /myrepo on NFS share.
$ repo=nfsiso::nfs.example.com:/mydir/rhel6.iso


dpkg-depcheck
debsign
dscverify
diff2patches

deb file:/home/jason/debian stable main contrib non-free

deb file:/home/jason/debian stable main contrib non-free
deb-src file:/home/jason/debian unstable main contrib non-free


apt-ftparchive packages directory | gzip > Packages.gz


Debug::Acquire::cdrom _________ # Print information related to accessing cdrom:// sources.
Debug::Acquire::ftp ___________ # Print information related to downloadingPackages using FTP.
Debug::Acquire::http __________ # Print information related to downloadingPackages using HTTP.
Debug::Acquire::https _________ # Print information related to downloadingPackages using HTTPS.
Debug::Acquire::gpgv __________ # Print information related to verifying cryptographic signatures using gpg.
Debug::aptcdrom _______________ # Output information about the process of 
								 --> accessing collections ofPackages stored on CD-ROMs.
Debug::BuildDeps __________ # Describes the process of resolving build-dependencies in apt-get(8).
Debug::Hashes __________ # Output each cryptographic hash that is generated by the apt libraries.
Debug::IdentCDROM _____________ # Do not include information from statfs, namely the number of 
								 --> used and free blocks on the CD-ROM filesystem, when 
								 --> generating an ID for a CD-ROM.
Debug::NoLocking __________ # Disable all file locking. For instance, this will allow two instances of “apt-get
Debug::pkgAcquire __________ # Log when items are added to or removed from the global download queue.
Debug::pkgAcquire::Auth __________ # Output status messages and errors related to verifying checksums and cryptographic
								 --> signatures of downloaded files.
Debug::pkgAcquire::Diffs		# Output information about downloading and applyingPackage 
								 --> index list diffs, and errors relating toPackage index list diffs.
Debug::pkgAcquire::RRed			# Output information related to patching aptPackage lists 
								 --> when downloading index diffs instead of full indices.
Debug::pkgAcquire::Worker		# Log all interactions with the sub-processes that actually perform downloads.
Debug::pkgAutoRemove			# Log events related to the automatically-installed status of
								 --> Packages and to the removal of unusedPackages.
Debug::pkgDepCache::AutoInstall		# Generate debug messages describing whichPackages are being automatically installed to
									 --> resolve dependencies. This corresponds to the initial auto-install pass performed in,
									 --> e.g., apt-get install, and not to the full apt dependency resolver; see
Debug::pkgProblemResolver/var/cache/apt/archives
Debug::pkgDepCache::Marker			# Generate debug messages describing whichPackages are marked as keep/install/remove
Debug::pkgDPkgPM					# When invoking dpkg(1), output the precise command line with which it is being invoked,
									 --> with arguments separated by a single space character.
Debug::pkgDPkgProgressReporting			# Output all the data received from dpkg(1) on the status
################################# file descriptor and any errors encountered while parsing it.
Debug::pkgOrderList				## Generate a trace of the algorithm that decides the 
								 --> order in which apt should pass packages to dpkg(1).
Debug::pkgPackageManager			# Output status messages tracing the steps performed when invoking dpkg(1).

Debug::pkgPolicy			# Output the priority of eachPackage list on startup.

Debug::pkgProblemResolver			# Trace the execution of the dependency resolver (this applies only to what happens when
									# a complex dependency problem is encountered).

Debug::pkgProblemResolver::ShowScores		# list of all installedPackages with their calculated 
											# score used by the pkgProblemResolver
Debug::pkgDepCache::Marker

Debug::sourceList _________________________ # Print information about the vendors read from /etc/apt/vendors.list.
Dir::Etc::Preferences
Dir::Etc::PreferencesParts
APT::Default-Release "stable";
"NotAutomatic: yes"
"ButAutomaticUpgrades: yes"
"NotAutomatic: yes"


/etc/cron.daily/apt					# 

################################################################################################
priority 1			# "NotAutomatic: yes" but not as "ButAutomaticUpgrades: yes"
priority 100			# "NotAutomatic: yes" and "ButAutomaticUpgrades: yes" 
priority 500			# versions that are not installed and do not belong to the target release
priority 990			# versions that are not installed and belong to the target release.
priority 100 			# all installedPackage versions
priority 500 			# all uninstalledPackage versions

priority 1 			# if it is additionally marked as 
priority 100			# "ButAutomaticUpgrades: yes"
priority 500  			# Then thePackage will be upgraded when apt-get install some-package
priority 990)			# or apt-get upgrade is executed.
################################################################################################



################################################################################################
P >= 1000			# causes a version to be installed even if this constitutes 
					# a downgrade of the Package

990 <= P < 1000		# causes a version to be installed even if it does not come 
					# from the target release, unless the installed version is more recent

500 <= P < 990		# causes a version to be installed unless there is a version available belonging to the
					# target release or the installed version is more recent

100 <= P < 500		# causes a version to be installed unless there is a version available belonging to some
					# other distribution or the installed version is more recent

0 < P < 100			# causes a version to be installed only if there is no installed version of thePackage

P < 0				# prevents the version from being installed
################################################################################################







Package: perl
Pin: version 5.10*
Pin-Priority: 1001

Package: *
Pin: origin ""
Pin-Priority: 999

Package: *
Pin: origin "ftp.de.debian.org"
Pin-Priority: 999

Package: *
Pin: release a=unstable
Pin-Priority: 50

Package: *
Pin: release n=jessie
Pin-Priority: 900

Package: *
Pin: release a=stable, v=7.0
Pin-Priority: 500

Package: gnome* /kde/
Pin: release n=experimental
Pin-Priority: 500

Package: *
Pin: release n=precise*
Pin-Priority: 990

Explanation: Uninstall or do not install any Debian-originated
Explanation:Package versions other than those in the stable distro
Package: *
Pin: release a=stable
Pin-Priority: 900

Package: *
Pin: release o=Debian
Pin-Priority: -10
apt-get installPackage/testing
apt-get installPackage/unstable

Package: perl
Pin: version 5.10*
Pin-Priority: 1001

Package: *
Pin: origin ""
Pin-Priority: 999

Package: *
Pin: release unstable
Pin-Priority: 50

Archive: stable
Suite: stable
Pin: release a=stable
Codename: wheezy
Pin: release n=wheezy
Version:
Pin: release v=7.0
Pin: release a=stable, v=7.0
Pin: release 7.0
Component: main
Pin: release c=main
Pin: release o=Debian
Pin: release l=Debian













apt_preferences
dpkg --add-architecture



dpkg-source
dpkg-source -x filename.dsc [output-directory]      	# Extract a source package.
dpkg-source -p<sign-command>      						# sign .dsc and/or .changes files (default is gpg).
dpkg-source -k0xF1E48A9B26B68A1F    					# the key to use for signing.

dpkg-source -p
dpkg-source =k

dpkg-depcheck -b 
--build-depends
--list-files
--strace-output=
--strace-input=


dpkg-buildpackage

echo -e "\t<<+}==========  ================{+>>"
gpg --clearsign -o InRelease Release
gpg -abs -o Release.gpg Release


echo -e "\t<<+}==========  ================{+>>"
dpkg-source --require-valid-signature			# abort if the package doesn't have a valid signature


dpkg-sig --sign <SIGNING_NAME>       	# Sign files 
dpkg-sig --verify							# Verify signatures on files
dpkg-sig --verify-role
dpkg-sig --verify-exact

dpkg-sig --list							# List signatures on files
dpkg-sig --get-hashes					# Get hashes file for files
dpkg-sig --sign-hashes <HASHES_FILE> 	# Sign hashes file
dpkg-sig --write-hashes <HASHES_FILE> 	# Write sigs from signed hashes file


dpkg-sig -k 0xF1E48A9B26B68A1F			Specify keyid to use when signing
dpkg-sig --verbose                     Makes dpkg-sig more verbose
dpkg-sig --also-v3-sig					Verify sigs from dpkg-sig 0.3-0.10


echo -e "\t<<+}==========  ================{+>>"
debsums --generate=all
debsums --generate=missing

echo -e "\t<<+}==========  ================{+>>"
debsums -l			# List installed packages with no checksums.
debsums -ca			# List  changed package files from all 

echo -e "\t<<+}========== List changed configuration files.  ================{+>>"
echo -e "\t<<+}========== & installed packages with checksums. ================{+>>"
debsums -ce
echo -e "\t<<+}===== As above, using sums from cached debs where available. ====={+>>"
debsums -cagp /var/cache/apt/archives		

echo -e "\t<<+}========== Reinstalls packages with changed files. ================{+>>"
apt-get install --reinstall $(dpkg -S $(debsums -c) | cut -d : -f 1 | sort -u)


################################################################################
===============================================================================
################################################################################



debsums/apt-autogen to be "true".

       This will create /etc/apt/apt.conf.d/90debsums as:

              DPkg::Post-Invoke {
                  "debsums --generate=nocheck -sp /var/cache/apt/archives";
              };



################################################################################
===============================================================================
################################################################################


Keyring of local trusted keys, new keys will be added here.
           Configuration Item: Dir::Etc::Trusted.

/etc/apt/trusted.gpg

Configuration Item Dir::Etc::TrustedParts.
echo -e "\t<<+}========== File fragments for the trusted keys, ================{+>>"
echo -e "\t<<+}======= Configuration Item Dir::Etc::TrustedParts. ================{+>>"
/etc/apt/trusted.gpg.d/


echo -e "\t<<+}========== Local trust database of archive keys. ================{+>>"
/etc/apt/trustdb.gpg

echo -e "\t<<+}========== Keyring of Debian archive trusted keys ================{+>>"
/usr/share/keyrings/debian-archive-keyring.gpg

/usr/share/keyrings/debian-keyring.gpg
/usr/share/keyrings/debian-maintainers.gpg



echo -e "\t<<+}==========  ================{+>>"

gpgdir --encrypt <directory> 		# Recursively encrypt all files in <directory> and all subdirectories.
gpgdir --decrypt <directory>		# Recursively decrypt all files in <directory> and all subdirectories.
gpgdir --sign <directory> 			# Recursively sign all files in <directory> and all subdirectories.
gpgdir --verify
gpgdir --Key-id 0xF1E48A9B26B68A1F			# Specify GnuPG key ID, or key-matching string. This overrides the use_key value in ~/.gpgdirrc
gpgdir --Default-key				# Use the key that GnuPG defines as the ~/.gnupg/ dir).
gpgdir --agent 					# Acquire password information from a running instance of gpg-agent.
gpgdir --Agent-info <info>			# Specify the value for the GPG_AGENT_INFO environment variable as returned by 'gpg-agent --daemon'.
gpgdir --gnupg-dir <dir>			# Specify a path to a .gnupg directory for gpg keys (the default is ~/.gnupg if this


gpg --show-session-key
gpg --list-key
gpg --list-sig
gpg --check-sig
gpg --list-trustdb
gpg --default-key
gpg --show-keyring
gpg --primary-keyring


gpg --keyid-format long 


gpg --fingerprint --list-secret-keys 0xF1E48A9B26B68A1F
gpg --verify
gpg --verify-files
gpg --list-keys
gpg --list-public-keys
gpg --list-sigs
gpg --check-sigs
gpg --fingerprint
gpg --list-secret-keys
gpg --check-sig
gpg --list-key
gpg --list-sig
gpg --homedir
gpg --show-session-key
gpg --no-auto-key-retrieve
gpg --default-cert-check-level


glob
debsig-verify
debsign
aptitude
apt-key
apt-utils
apt-ftparchive


dpkg-architecture
debuild


--debs-dir

DEBSIGN_PROGRAM
DEBSIGN_MAINT
              This is the -m option.

       DEBSIGN_KEYID
              And this is the -k option.

       DEBSIGN_ALWAYS_RESIGN
       

--path-exclude=/usr/share/doc/*
--path-include=/usr/share/doc/*/copyright
--path-exclude=glob-pattern
--path-include=glob-pattern
--pre-invoke=command
--post-invoke=command
--instdir=dir


env - PATH="$PATH" foo
env DISPLAY=gnu:0 LOGNAME=foo nemacs



/var/lib/dpkg/status
/etc/dpkg/dpkg.cfg.d/[0-9a-zA-Z_-]*
/etc/dpkg/dpkg.cfg
~/.dpkg.cfg



uri distribution
apt-transport-method
apt-transport-debtorrent
rsh

deb file:/home/jason/debian stable main contrib non-free


deb http://ftp.tlh.debian.org/universe unstable/binary-$(ARCH)/
deb [ arch=amd64 ] http://ftp.debian.org/debian wheezy main



APT_CONFIG
apt.conf(5)
apt-config -o dir::cache=/tmp
shell 							# Shell mode
dump 							# Show the configuration

man 8 apt-config 
man 5 apt_preferences

Run-Directory			# 
Build-options			# These options are passed to dpkg-buildpackage(1) when compilingPackages


dpkg-scansources
dpkg-scanpackages
apt-ftparchive
Check-Valid-Until
dpkg --audit




dpkg-depcheck -b debian/rules build



dscverify
dscextract
dget
debuild
desktop2menu
debsign,
debcheckout
cvs-debuild
dcontrol
dd-list
cvs-debrelease

dctrl-tools


##### dscverify
#
# A colon separated list of extra keyrings to read.
# DSCVERIFY_KEYRINGS=""

##### getbuildlog
#
# No variables currently

##### grep-excuses
#
# This specifies a default maintainer name or email to hunt for
# GREP_EXCUSES_MAINTAINER=""
#
# Is this running on ftp-master.debian.org?  If so, we use the local
# excuses file
# GREP_EXCUSES_FTP_MASTER=no


# This key ID takes precedence over the rest
# DPKGSIG_KEYID=
#
# Do we sign the .changes and .dsc files?  See the manpage for more
# info.  Valid options are no, auto, yes, full and force_full.
# DPKGSIG_SIGN_CHANGES=auto
#
# Do we cache the gpg passphrase by default?  This can be dangerous!
# DPKGSIG_CACHE_PASS=no

##### dpkg-depcheck
#
# Extra options given to dpkg-depcheck before any command-line
# options specified.  For example: "-b --features=-catch-alternatives"
# DPKG_DEPCHECK_OPTIONS=""

##### dpkg-genbuilddeps
#
# No variables currently

##### dpkg-sig
#
# dpkg-sig is not a part of devscripts, but shares this configuration file.
# It pays attention to the values of DEBSIGN_MAINT and DEBSIGN_KEY in
# addition to the following.


# DEBUILD_DPKG_BUILDPACKAGE_HOOK=""
# DEBUILD_CLEAN_HOOK=""
# DEBUILD_DPKG_SOURCE_HOOK=""
# DEBUILD_BUILD_HOOK=""
# DEBUILD_BINARY_HOOK=""
# DEBUILD_FINAL_CLEAN_HOOK=""
# DEBUILD_LINTIAN_HOOK=""
# DEBUILD_SIGNING_HOOK=""
# DEBUILD_POST_DPKG_BUILDPACKAGE_HOOK=""

##### dget
#
# Extra directories to search for files in addition to
# /var/cache/apt/archives.  This is a colon-separated list of directories.
# DGET_PATH=""
#
# Unpack downloaded source packages
# DGET_UNPACK=yes
#
# Verify source package signatures using dscverify
# DGET_VERIFY=yes




















#####################################################################################
rpm --verify 			# Verify the installed package(s)
rpm -a 						# Verify all installed packages against the RPM database
rpm --dbpath				# <path> Use <path> to find RPM database
rpm -f <file>				# Verify package owning <file>
rpm -g <group>				# Verify the packages belonging to <group>
rpm --nodeps 				# Do not check dependencies during verification
rpm --nofiles 				# Do not verify file attributes
rpm --noscripts 			# Do not execute verification scripts
rpm -p <file> (or “-”) 		# Verify against a specific package <file>
rpm --rcfile <rcfile> 		# Set alternate rpmrc file to <rcfile>
rpm --root <path> 			# Set alternate root to <path>
rpm -v 						# Display additional information
rpm -vv 					# Display debugging information
#####################################################################################
rpm -q or --query 				# Query the installed package(s)
rpm -a 							# Query all installed packages
rpm -c 							# Display a list of configuration files
rpm -d 							# Display a list of documentation files
rpm --dbpath <path> 			# Use <path> to find RPM database
rpm --dump 						# Display all verifiable information about each file
rpm -f <file> 					# Query package owning <file>
rpm -g <group> 					# Query packages belonging to <group>
rpm -i 							# Display summary package information
rpm -l 							# Display a list of the files in a package
rpm <null> 						# Display full package label
rpm -p <file> (or “-”) 			# Query a package <file> (URLs are okay here)
rpm --provides 					# Display the capabilities the package provides
rpm --qf or --query				# format Display the queried data in a custom format
rpm -R or --requires 			# Display the capabilities requirement of the package
rpm --rcfile <rcfile> 			# Set alternate rpmrc file to <rcfile>
rpm -s 							# Displays the state of each file in the package
rpm --scripts 					# Show the scripts associated with a package
#####################################################################################
rpm -Va |more


echo "$1" | sed -e 's://*:/:g'


echo "$1" | grep -q '^.*\.cpio\..*' && is_cpio_compressed="compressed"

echo "$1" | sed 's/^.*\.cpio\(\..*\)\?/cpio/'

echo "$output_file" | grep -q "\.gz$" && compr="gzip -n -9 -f"
echo "$output_file" | grep -q "\.bz2$" && compr="bzip2 -9 -f"
echo "$output_file" | grep -q "\.lzma$" && compr="lzma -9 -f"
echo "$output_file" | grep -q "\.xz$" && \
compr="xz --check=crc32 --lzma2=dict=1MiB"
echo "$output_file" | grep -q "\.lzo$" && compr="lzop -9 -f"
echo "$output_file" | grep -q "\.cpio$" && compr="cat"




dpkg --list | grep openssh
yum list installed | grep ssh





/etc/yum.conf

[main]
cachedir=/var/cache/yum/$basearch/$releasever
keepcache=0
debuglevel=2
logfile=/var/log/yum.log
exactarch=1
gpgcheck=1
plugins=1





Checking /etc/yum.repos.d/*.repo files
[myrepo]
name=My repository of software packages
baseurl=http://myrepo.example.com/pub/myrepo
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/MYOWNKEY





yum search 
yum info 
yum list available
yum list 
yum provides 
yum list all
yum deplist emacs | less
yum erase 
yum history info
yum check-update
yum update
yum update cups
yum grouplist | less
yum groupinfo LXDE
yum groupinstall LXDE
yum groupremove LXDE
yum clean packages


yum clean metadata
yum clean all
yum check
yumdownloader --verbose --resolve 


/etc/yum.conf


rpm -qa | grep



rpm2cpio   > poo.cpio
cpio -ivd < poo.cpio





















