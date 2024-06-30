> [[Wiki|Home]] ▸ [[GPG and PGP]] ▸ **Signing Git commits using GPG keys**

**Signing Git commits using GPG keys** is the process of using a cryptographic identity to assert that a given change to a piece of software was made by a given individual, organization, or other entity. This is accomplished by associating a (cryptographic) [digital signature](https://simple.wikipedia.org/wiki/Digital_signature) with the commit (software patch) itself. Other users of the software (like you) can then validate that the software being patched was modified only by sources they trust.

> 🔰📖 GPG is also known as *PGP*. For the purposes of this guide, we will be referring to the tool as **GPG**. For further information on the difference between the initialisms, see [[GPG and PGP]].

> :beginner: :bulb: This procedure requires the use of a command line. If you are unfamiliar with the command line, we recommend you take some time to work through the excellent [Foundations: Command Line Basics course offered for free by Tech Learning Collective](https://techlearningcollective.com/foundations/), or another tutorial series such as [Taming the Terminal](https://www.bartbusschots.ie/s/blog/taming-the-terminal/).

# Contents

1. [Overview](#overview)
1. [Procedure](#procedure)
    1. [Step 1: Generate a GPG keypair](#step-1-generate-a-gpg-keypair)
    1. [Step 2: Configure Git or a specific Git project](#step-2-configure-git-or-a-specific-git-project)
    1. [Step 3: Set a git commit alias](#step-3-set-a-git-commit-alias)
1. [See also](#see-also)

# Overview

In brief, to sign Git commits with a GPG key, you must first have (or generate) a GPG key pair. Each GPG key pair is uniquely identified by a *fingerprint* (also called a *key ID*), which is represented by a string of 40 hexadecimal characters. The GPG keys you have access to are stored on your computer in a structure called a GPG *keyring*. To view your keyring from a command line you invoke the `gpg` command-line program with the `--list-keys` or `--list-secret-keys` options to list all keys in your keyring or only the keys to which you have an associated private ("secret") part, respectively.

Once you have a GPG key, you must then inform the `git` program on your computer to use the key of your choice when signing commits. Finally, you must ensure that your invocations to the [`git commit` command](https://git-scm.com/docs/git-commit) tell Git to sign the commit. This is most easily accomplished by aliasing `git commit` to `git commit --gpg-sign` or an equivalent.

Additionally, if you plan on using this key for a project hosted by GitHub.com, you will need a GitHub account. See our [[New member orientation guide § GitHub|New member orientation guide#github]] advice for instructions on creating a personal and/or pseudonymous GitHub account.

# Procedure

The following outlines the exact process for generating a good GPG keypair, followed by telling `git` which one to use, with [[operational security|OPSEC]] considerations included. We assume you will be performing these steps from a laptop or desktop computer. You *can* [generate GPG keys from mobile devices such as Android smartphones](https://www.openkeychain.org/), but we find it difficult to write code from a mobile device. :)

## Step 1: Generate a GPG keypair

Before you can use a GPG key, you must have one to use. This section describes the process for generating an OpenPGP-compatible keypair (i.e., a GPG keypair) that can be used by all standards-compliant GPG or PGP programs, such as `git`.

> :beginner::warning: Your GPG key, just like the username and password combination to your account, can reveal your identity (because it _is_ an identity). Therefore, we recommended making different GPG keys for each of your GitHub (or GitLab, etc.) accounts that you wish to compartmentalize from one another. In other words, do not use your personal GPG key with your pseudonymous GitHub account, or vice versa. We are, of course, assuming you probably don't want to sign your day job's code commits with your anti-cop GPG key, unless your boss is down. :black_flag:

1. Ensure you have the `gpg` (or `gpg2`) program installed. In a terminal, enter:
    ```sh
    gpg --version
    ```
    > 🔰 💡 If you do not have a `gpg` binary in your shell's search path, check for `gpg2 --version`, as some systems install the program under this slightly different name. If you prefer to use `gpg2` over `gpg`, you'll also need to inform `git` to use this alternative name. This can be accomplished by setting the `gpg.program` Git configuration option:
    > ```sh
    > git config --global gpg.program gpg2
    > ```
    1. If you do not already have `gpg` or `gpg2`, install it:
        1. macOS users can install GPG via [MacPorts](https://www.macports.org/) using `port install gnupg2`, via [Homebrew](https://brew.sh/) using `brew install gnupg`, or with a graphical user interface from [GPGTools.org](https://gpgtools.org/).
        1. GNU/Linux users can install GPG via their operating system's default package repositories. Users of Debian-based GNU/Linux distributions such as Ubuntu:
            ```sh
            sudo apt update && sudo apt install gnupg2
            ```
        1. Windows users can install [GPG4Win](https://www.gpg4win.org/), which installs a command line executable as well as equivalent GUI tools.
1. Initiate the interactive key generation process, which will prompt you for specifics about your desired new key:
    ```sh
    gpg --full-gen-key
    ```
1. Select a type of key. We suggest making an RSA keypair (typically also the default).
    > :bulb: It is possible to sign commits with different types of GPG keys, however, as of this writing, GitHub itself suggests using RSA keys that are 4096 bits long. A 4096-bit long RSA key is secure enough for these purposes.
1. Select a key length. Type in `4096` and hit `Enter` to make a 4096-bit long key.
1. Select how long you want this key to be valid for. Pick a time frame that makes sense for the use of the key; 2 years, for example, is long enough to be useful but not so long as to risk perpetual use if a vulnerability should be found or a compromise should occur later on.
1. Confirm your chosen expiry date.
1. Enter the details of your chosen cryptographic identity. If you're using this key to sign commits on a public repository, or on GitHub generally, try to match the information that you've already given GitHub (or whatever service), so that you're not unnecessarily giving out more personal information than needed.
1. Finally, choose a (strong!) password to protect the private portion of your GPG keypair.
> :beginner::bulb: Choosing strong passwords is always important, so we strongly encourage the [use of a password/secrets management application](https://github.com/AnarchoTechNYC/meta/tree/main/train-the-trainers/mr-robots-netflix-n-hack/week-2/strengthening-passwords-to-defend-against-john#using-a-password-manager) such as [Bitwarden](https://bitwarden.com/), KeePass, [etc](https://prism-break.org/en/all/#password-managers). Most password managers also feature the ability to generate strong passwords.

Repeat the above step for each independent identity you wish to create. For instance, if you have a distinct "professional" GitHub account separate from a "personal" or "activist" GitHub account, make a dedicated GPG key for each account. **Take care not to pollute one of your identities with artifacts from the other.** At worst, this will de-anonymize you. At best, it will offer an adversary additional information with which to correlate your behaviors across your various (no-longer-secret) identities.

You can now sign commits with your newly generated key by invoking `git` with the `-S` or `--gpg-sign` option, passing your key ID as the value to the `-S` or `--gpg-sign` options. For example:

```sh
git commit --gpg-sign=C42F2F04C42D489E23DD71CE07EFAA28AB94BC85
```

Continue to the next steps to simplify this command line quite a bit.

## Step 2: Configure Git or a specific Git project

Once you have a GPG keypair with which to use to sign commits, you may want to configure your installation of the Git source code management tool, or a specific Git repository, to automatically use that key when you commit changes to the code.

> :bulb: This step is optional, but recommended.

1. Find the fingerprint of the GPG key you'd like to use to sign commits with.
    ```sh
    gpg --list-secret-keys --keyid-format LONG
    ```
1. Navigate to the folder containing your Git project.
1. Inform `git` of the GPG key you'd like to use to sign commits to this project. Assuming your GPG key ID is `C42F2F04C42D489E23DD71CE07EFAA28AB94BC85`, you would invoke `git config` as follows:
    ```sh
    git config user.signingKey C42F2F04C42D489E23DD71CE07EFAA28AB94BC85
    ```

> :beginner: :warning: Many Git and GPG guides will tell you to use the command `git config` with the `--global` option to write the configuration into your home directory's `.gitconfig` file. Their advice is intened to simplify your use of `git`, but means that your key selection will apply by default (i.e., every commit will be signed using this key unless a specific project's `.git/config` file overrides that selection). This can be a potential operational security risk if you're trying to keep one GitHub account relatively separate from another. This is why we prefer the use of per-repository configurations over user account-wide ("global") configurations.

You can now sign commits with your newly generated key by invoking `git` with the `-S` or `--gpg-sign` option, without the need to pass your key ID on the command line. For example:

```sh
git commit -S
```

The above is enough to automatically select your configured signing key and create a GPG-signed commit.

## Step 3: Set a git commit alias

To further reduce repetitive typing, some people choose to set up a [Git command alias](https://git-scm.com/book/en/v2/Git-Basics-Git-Aliases).

> :bulb: This step is purely optional.

1. Navigate to the folder containing your Git project.
1. Configure a `git` alias:
    ```
    git config alias.cs "commit -S"
    ```

You can now sign commits with your newly generated key by invoking `git` with your new alias:

```sh
git cs
```

The above is now enough to enable GPG commit signing with your pre-configured chosen key.

# See also

* [:globe_with_meridians: GitHub Help: Generating a new GPG key](https://help.github.com/articles/generating-a-new-gpg-key/)
* [:globe_with_meridians: Github Help: Telling Git about your GPG key](https://help.github.com/articles/telling-git-about-your-gpg-key/)
