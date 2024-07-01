# Awesome Github OSINT

## [nil0x42](https://twitter.com/nil0x42)'s tips & tricks

#### :scroll: [get-github-followers-twitter.py](https://gist.github.com/nil0x42/df824d885d884f0b5c5c0da2be475076)
* Scrape twitter account of all github followers of **target user** on GitHub

#### :scroll: [get-github-stargazers-twitter.py](https://gist.github.com/nil0x42/e0126ed2fe7e7197e7c15c6bb05021e6)
* Scrape twitter account of all stargazers of **target project** on GitHub

#### :scroll: [Get_Early_Stargazers.graphql](https://gist.github.com/nil0x42/656ccf98c00c99277ca7826bf1c43022)
* Get list of first people who have added a star on a github project. **Helpful for investigation**, as early stargazers are likely to be closely connected to **target user/organisation** owning the project...

----------

## Projects

#### :octocat: https://github.com/needmorecowbell/giggity ![](https://badgen.net/github/stars/needmorecowbell/giggity)
* grab hierarchical data about a github organization, user, or repo
  
#### :octocat: https://github.com/vulnbe/github-osint ![](https://badgen.net/github/stars/vulnbe/github-osint)
* This tool uses GitHub API to get email addresses from commit log of user/organisation repositories
It can be operated with/without GitHub API token.

#### :octocat: https://github.com/s0md3v/Zen ![](https://badgen.net/github/stars/s0md3v/Zen)
* Find email addresses of Github users

#### :octocat: https://github.com/x1sec/commit-stream ![](https://badgen.net/github/stars/x1sec/commit-stream)
* commit-stream drinks commit logs from the Github event 
firehose exposing the author details (name and email address) associated
 with Github repositories in real time.

#### :octocat: https://github.com/antnks/enumerate-github-users ![](https://badgen.net/github/stars/antnks/enumerate-github-users)
* A script to create fake commits, with emails of your choice. GitHub 
automatically resolves the emails to a GitHub accounts associated with 
them. This way if you know an email you can find the GitHub account of a
 user.

#### :octocat: https://github.com/michenriksen/gitrob ![](https://badgen.net/github/stars/michenriksen/gitrob)
* Gitrob is a tool to help find potentially sensitive files pushed to 
public repositories on Github. Gitrob will clone repositories belonging 
to a user or organization down to a configurable depth and iterate 
through the commit history and flag files that match signatures for 
potentially sensitive files. The findings will be presented through a 
web interface for easy browsing and analysis.

#### :octocat: https://github.com/tillson/git-hound ![](https://badgen.net/github/stars/tillson/git-hound)
* Reconnaissance tool for GitHub code search. Finds exposed API keys using
pattern matching, commit history searching, and a unique result scoring
system.

#### :octocat: https://github.com/BishopFox/GitGot ![](https://badgen.net/github/stars/BishopFox/GitGot)
* Semi-automated, feedback-driven tool to rapidly search through troves of public data on GitHub for sensitive secrets.
    
#### :octocat: https://github.com/hisxo/gitGraber ![](https://badgen.net/github/stars/hisxo/gitGraber)
* gitGraber: monitor GitHub to search and find sensitive data in real time
for different online services such as: Google, Amazon, Paypal, Github, 
Mailgun, Facebook, Twitter, Heroku, Stripe...

#### :octocat: https://github.com/eth0izzle/shhgit ![](https://badgen.net/github/stars/eth0izzle/shhgit)
* shhgit finds committed secrets and sensitive files across 
GitHub, Gists, GitLab and BitBucket or your local repositories in real 
time.

#### :octocat: https://github.com/nielsing/yar ![](https://badgen.net/github/stars/nielsing/yar)
* yar is an OSINT tool for reconnaissance of
repositories/users/organizations on Github. Yar clones repositories of
users/organizations given to it
and goes through the whole commit history in order of commit time, in
search for secrets/tokens/passwords, essentially anything that shouldn't
be there. Whenever yar finds a secret,
it will print it out for you to further assess.

#### :octocat: https://github.com/dxa4481/truffleHog ![](https://badgen.net/github/stars/dxa4481/truffleHog)
* Searches through git repositories for secrets, digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
* **Right now a breaking change in GitPython is causing an error in pip installations.**

#### :octocat: https://github.com/zricethezav/gitleaks ![](https://badgen.net/github/stars/zricethezav/gitleaks)
* Scan git repos for secrets using regex and entropy

#### :octocat: https://github.com/anshumanbh/git-all-secrets ![](https://badgen.net/github/stars/anshumanbh/git-all-secrets)
* A tool to capture all the git secrets by leveraging multiple open source git searching tools

#### :octocat: https://github.com/Hell0W0rld0/Github-Hunter ![](https://badgen.net/github/stars/Hell0W0rld0/Github-Hunter)
* This tool is for sensitive information searching on Github

#### :octocat: https://github.com/paulirish/github-email ![](https://badgen.net/github/stars/paulirish/github-email)
* Retrieve a GitHub user's email even if it's not public.
* Pulls info from Github user, NPM, activity commits, owned repo commit activity.

#### :octocat: https://github.com/techgaun/active-forks ![](https://badgen.net/github/stars/techgaun/active-forks)
* This project allows you to find the most active forks of a repository.
* Live Demo: https://techgaun.github.io/active-forks/index.html

#### :octocat: https://github.com/hodgesmr/FindGitHubEmail ![](https://badgen.net/github/stars/hodgesmr/FindGitHubEmail)
* Find the email address of any GitHub user

#### :octocat: https://github.com/atmoner/githubFind3r ![](https://badgen.net/github/stars/atmoner/githubFind3r)
* githubFind3r is a very fast command line repo/user/commit search tool

#### :octocat: https://github.com/gwen001/github-subdomains ![](https://badgen.net/github/stars/gwen001/github-subdomains)
* Find subdomains on GitHub.

#### :octocat: https://github.com/duo-labs/secret-bridge ![](https://badgen.net/github/stars/duo-labs/secret-bridge)
* Monitors Github for leaked secrets

#### :octocat: https://github.com/obheda12/GitDorker ![](https://badgen.net/github/stars/obheda12/GitDorker)
* A Python program to scrape secrets from GitHub through usage of a large repository of dorks.

#### :octocat: https://github.com/UnkL4b/GitMiner ![](https://badgen.net/github/stars/UnkL4b/GitMiner)
* Tool for advanced mining for content on Github

----------

## Articles

#### https://medium.com/@shahjerry33/github-recon-its-really-deep-6553d6dfbb1f
* Talks about manual & automated leak search & GitHub dorking
