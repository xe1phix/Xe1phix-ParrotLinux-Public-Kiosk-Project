PARSING JSON FILE

sudo apt-get install -y jq
curl -s 'https://api.github.com/users/lambda' | jq -r '.name'
 
grep -w \"key_name\" /vagrant/test.json |tail -1 | cut -d\" -f4
grep -w \"author\" /vagrant/test.json |tail -1 | cut -d\" -f4

$ FOOBAZ="tester"
$ jq -n --arg foobaz "$FOOBAZ" '{"foobaz":$foobaz}' > test1.json
$ cat test1.json

export $(jq -r '@sh "FOO=\(.foo) BAZ=\(.baz)"') #fill environment variables from JSON object keys (e.g. $FOO from jq query ".foo")
echo '{ "foo": 123, "bar": 456 }' | jq '.foo' #print out the foo property
apod_url=$(curl -s https://api.nasa.gov/planetary/apod?api_key=DEMO_KEY | jq -r '.hdurl') #get the URL of the current Astronomy Picture of the Day (APOD)
echo '{ "Version Number": "1.2.3" }' | jq '."Version Number"' #if a property has a spaces or weird characters
echo '[1,2,3]' | jq '.[]' #how iteration works
echo '[ {"id": 1}, {"id": 2} ]' | jq '.[].id' #access a property on each item
echo '{ "a": 1, "b": 2 }' | jq '.[]' #the value of each key/value pair
