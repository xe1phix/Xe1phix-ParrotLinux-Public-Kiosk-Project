curl -kL http://localhost/
curl -IL http://localhost
HTTP/1.1 200 OK
Server: nginx/1.10.2

curl -Is http://www.google.com | head -n 1 #check whether a web site is up, and what status message the web server is showing
curl -sSf http://example.org > /dev/null
curl -XGET 'localhost:9200/?pretty'

curl -X PUT "http://127.0.0.1:9200/mytest_index" #sending data with POST and PUT requests
curl -d "param1=value1&param2=value2" -X POST http://localhost:3000/data
curl -d "param1=value1&param2=value2" -H "Content-Type: application/x-www-form-urlencoded" -X POST http://localhost:3000/data
curl -d "@data.txt" -X POST http://localhost:3000/data
curl -d '{"key1":"value1", "key2":"value2"}' -H "Content-Type: application/json" -X POST http://localhost:3000/data
curl -d "@data.json" -X POST http://localhost:3000/data

# check if apache is running
curl -sf http://webserver/check_url
