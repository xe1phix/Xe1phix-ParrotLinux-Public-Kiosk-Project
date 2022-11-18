pushd #stores a directory path in the directory stack,adds directory paths onto a directory stack (history), allows you to navigate back to any directory in history
pushd +2 #use the directory index in the form pushd +# or pushd -# to add directories to the stack and move into
popd #removes the top directory path from the same stack
popd +1 #remove a directory from the directory stack inded use popd +# or popd -#
dirs #display directories in the directory stack (or history)
dirs -v

pushd $(pwd) && cd /opt
popd
