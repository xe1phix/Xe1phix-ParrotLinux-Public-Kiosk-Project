fork the F-Droid server project




# Prerequisites
sudo apt-get install openjdk-8-jdk subversion git git-svn \
    mercurial bzr virtualbox ruby ruby-dev vagrant python3 python3-paramiko \
    python3-pil python3-pyasn1-modules python3-clint
vagrant plugin install vagrant-cachier
ln -s ~/Android/Sdk/build-tools/23.0.2/aapt ~/Android/Sdk/platform-tools/

# Get the code
cd ~/code
git clone https://gitlab.com/fdroid/fdroidserver.git
git clone https://gitlab.com/fdroid/fdroiddata.git
echo 'export PATH="~/code/fdroidserver:$PATH"' >> ~/.profile
source ~/.profile

# Config
cd fdroiddata
cp ../fdroidserver/examples/config.py ./
chmod 0600 config.py
echo 'sdk_path = "$HOME/Android/Sdk"' >> config.py

# Set up Vagrant build box
cd ../fdroidserver
cp ./examples/makebuildserver.config.py ./
./makebuildserver
# Now wait several hours for this to finish

# Build a package (the F-Droid client) just to check it works
cd ../fdroiddata
mkdir repo
fdroid update --create-key
fdroid readmeta  # Should give no output if it worked
fdroid build --server org.fdroid.fdroid

Make your own package

Below I’m using my own package, Rabbit Escape, as an example. Its Android code is inside rabbit-escape-ui-android/app, whereas many programs will just have it directly in a directory called “app”.

Rabbit Escape also builds non-Android-specific Java and other things during its build, so your package may be simpler.

cd ../fdroiddata
fdroid import --url https://github.com/andybalaam/rabbit-escape \
    --subdir rabbit-escape-ui-android/app

Now edit the new file that was created - in my case it was called metadata/net.artificialworlds.rabbitescape.txt.

I set the following info:

Categories:Games
License:GPL-2.0-or-later
Author Name:Andy Balaam and the Rabbit Escape developers
Author Email:rabbitescape@artificialworlds.net
Web Site:http://artificialworlds.net/rabbit-escape
Source Code:https://github.com/andybalaam/rabbit-escape
Issue Tracker:https://github.com/andybalaam/rabbit-escape/issues

Name:Rabbit Escape
Summary:Lemmings-like puzzle/action game
Description:
140 levels of puzzling action!
 ... blah blah ...
.

Repo Type:git
Repo:https://github.com/andybalaam/rabbit-escape
Binaries:https://github.com/andybalaam/rabbit-escape/releases/download/v%v/rabbit-escape-%v.apk

Build:0.10.2,102
    commit=v0.10.2
    subdir=rabbit-escape-ui-android/app
    gradle=paid
    build=cd ../.. && \
        make android-pre-fdroid

Auto Update Mode:Version v%v
Update Check Mode:Tags v\d+\.\d+(\.\d+)?
Current Version:0.10.2
Current Version Code:102

For more info, see the F-Droid Build Metadata Reference.
https://f-droid.org/en/docs/Build_Metadata_Reference


And then checked it all worked with:

cd ../fdroiddata
fdroid lint net.artificialworlds.rabbitescape
fdroid readmeta
fdroid checkupdates net.artificialworlds.rabbitescape
fdroid rewritemeta net.artificialworlds.rabbitescape

When I got the version stuff right the checkupdates command printed:

INFO: Processing net.artificialworlds.rabbitescape...
INFO: ...updating to version 0.10.1 (101)
INFO: Finished.

Then I made sure it built OK:

fdroid build --server -v -l net.artificialworlds.rabbitescape







     fdroid checkupdates
    fdroid build
    fdroid update
    fdroid server update





Install fdroidserver, or just use it directly from master:

git clone https://gitlab.com/fdroid/fdroidserver.git
export PATH="$PATH:$PWD/fdroidserver"

Clone fdroiddata (or your fork) and enter it:

git clone https://gitlab.com/fdroid/fdroiddata.git
cd fdroiddata

Optionally create a base config.py and signing keys with:

fdroid init

Make sure fdroid works and reads the metadata files properly:

fdroid readmeta





https://f-droid.org/en/docs/Installing_the_Server_and_Repo_Tools


https://launchpad.net/~fdroid/+archive/ubuntu/buildserver/


https://f-droid.org/en/docs/Build_Server_Setup


https://gitlab.com/fdroid/fdroidserver/blob/master/jenkins-build-makebuildserver


https://jenkins.debian.net/job/reproducible_setup_fdroid_build_environment_profitbricks7/


https://f-droid.org/en/docs/Verification_Server/






https://f-droid.org/en/docs/Setup_an_F-Droid_App_Repo/






## generate a signing key for the repository index. 
keytool -genkey -v -keystore my.keystore -alias repokey \
  -keyalg RSA -keysize 2048 -validity 10000




Verify that your APK is signed:

apksigner verify my-app-release.apk





Create a signer repo out of an unsigned repo with:

jar cf index.jar index.xml
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore mytest.keystore index.jar mykeyalias


























