#list the file opened by process-id
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -p {}"

#list the file opened by process other than specified pid
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -p ^{}"

# list network services by process-id
ps aux | grep 'index.js' | grep -v 'grep' | awk '{ print $2 }' | xargs -I {} sh -c "lsof -i | grep {}"