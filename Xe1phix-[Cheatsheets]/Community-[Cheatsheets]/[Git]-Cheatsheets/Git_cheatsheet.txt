# Git_cheatsheet

_A comprehensive list of Git commands_


### Configure tooling
| Command | Description |
| ------- | ----------- |
| `git config --global user.name "[name]"` | Sets the name you want attached to your commit transactions |  
| `git config --global user.email "[email.address]"`| Sets the email you want attached to your commit transactions |


### Creating Repositories
| Command | Description |
| ------- | ----------- |
| `git init` | Initialize a local Git repository |
| `git clone url` | Create a local copy of a remote repository |

### Make changes
| Command | Description |
| ------- | ----------- |
| `git status` | Check status |
| `git add [file-name.txt]` | Add a file to the staging area |
| `git add -all` | Add all new and changed files to the staging area |
| `git commit -m "[commit message]"` | Commit changes |
| `git reset [file]`| Unstages the file, but preserves its contents |
| `git diff` | Show file differences not yet staged |
| `git diff --staged` | Shows file differences between staging and last file version |  


### Group changes
| Command | Description |
| ------- | ----------- |
| `git branch` | Lists all local branches in the current repository |
| `git branch [branch-name]` | Creates a new branch |
| `git checkout [branch-name]` | Switches to the specified branch and updates the working directory |
| `git merge [branch]` | Combines the specified branch's history into the current branch |
| `git branch -d [branch-name]` | Deletes the specified branch |

### Refactor filenames
| Command | Description |
| ------- | ----------- |
| `git rm [file]`| Deletes the file from the working directory and stages the deletion |
|`git rm --cached [file] | Removes the file from version control but preserves the file locally | 
| `git mv [file-original] [file-renamed]` | Changes the file name and prepares it for commit |  

### Branching & Merging

| Command | Description |
| ------- | ----------- |
| `git branch` | List branches (the asterisk denotes the current branch) |
| `git branch -a` | List all branches (local and remote) |
| `git branch [branch name]` | Create a new branch |
| `git branch -d [branch name]` | Delete a branch |
| `git push origin --delete [branchName]` | Delete a remote branch |
| `git checkout -b [branch name]` | Create a new branch and switch to it |
| `git checkout -b [branch name] origin/[branch name]` | Clone a remote branch and switch to it |
| `git checkout [branch name]` | Switch to a branch |
| `git checkout -` | Switch to the branch last checked out |
| `git checkout -- [file-name.txt]` | Discard changes to a file |
| `git merge [branch name]` | Merge a branch into the active branch |
| `git merge [source branch] [target branch]` | Merge a branch into a target branch |
| `git stash` | Stash changes in a dirty working directory |
| `git stash clear` | Remove all stashed entries |

### Sharing & Updating Projects
| Command | Description |
| ------- | ----------- |
| `git push origin [branch name]` | Push a branch to your remote repository |
| `git push -u origin [branch name]` | Push changes to remote repository (and remember the branch) |
| `git push` | Push changes to remote repository (remembered branch) |
| `git push origin --delete [branch name]` | Delete a remote branch |
| `git pull` | Update local repository to the newest commit |
| `git pull origin [branch name]` | Pull changes from remote repository |
| `git remote add origin ssh://git@github.com/[username]/[repository-name].git` | Add a remote repository |
| `git remote set-url origin ssh://git@github.com/[username]/[repository-name].git` | Set a repository's origin branch to SSH |

### Inspection & Comparison

| Command | Description |
| ------- | ----------- |
| `git log` | View changes |
| `git log --summary` | View changes (detailed) |
| `git diff [source branch] [target branch}` | Preview changes before merging |

### Review history
| Command | Description |
| ------- | ----------- |
| `git log` | View changes |
| `git log --follow [file]` | Lists version history for a file, including renames |
| `git diff [first-branch]..[second-branch]`| Shows content differences between two branches |
|`git show [commit]` | Outputs metadata and content changes of the specified commit |  


### Save fragments
| Command | Description |
| ------- | ----------- |
| `git stash` | Temporarily stores all modified tracked files |
| `git stash pop` | Restores the most recently stashed files |
| `git stash list` | Lists all stashed changesets |
| `git stash drop` | Discards the most recently stashed changeset |

### Redo commits
| Command | Description |
| ------- | ----------- |
| `git reset [commit-id]` | Undoes all commits after [commit], preserving changes locally |
| `git reset --hard [commit-id]` | Discards all history and changes back to the specified commit |