## Community-[Curl]-[OpenSSL]-[RSA]-[Public-Key]-[API]-Commands-[POST]+[PUT]-Cheatsheet.sh
# Use Case 1
#     Generate and store the public key of an RSA 2048 keypair using POST+PUT
# User Format: openssl default public key PEM.  (aka SubjectPublicKeyInfo inside a PEM file with header/footer)
# Transfer Format: None - File does not need to be encoded for transfer
# Content-Type: application/octet-stream
# Expected Format from Barbican: Identical PEM file

# Create the RSA keypair
openssl genrsa -out private.pem 2048

# Extract the public key
openssl rsa -in private.pem -out public.pem -pubout

# Submit a metadata-only POST
curl -vv -H "X-Auth-Token: $TOKEN" \
-H 'Accept: application/json' \
-H 'Content-Type: application/json' \
-d '{"name": "RSA Public Key",
     "secret_type": "public",
     "algorithm": "RSA"}' \
http://localhost:9311/v1/secrets | python -m json.tool

# Response
{
    "secret_ref": "http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb"
}

# GET metadata
curl -vv -H "X-Auth-Token: $TOKEN" \
-H 'Accept: application/json' \
http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb |
python -m json.tool

# Response
#  Note that content_types is missing.  It means the secret has no payload.
{
    "algorithm": "RSA",
    "bit_length": null,
    "created": "2015-04-09T20:37:42.764788",
    "creator_id": "3a7e3d2421384f56a8fb6cf082a8efab",
    "expiration": null,
    "mode": null,
    "name": "RSA Public Key",
    "secret_ref": "http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb",
    "secret_type": "public",
    "status": "ACTIVE",
    "updated": "2015-04-09T20:37:42.764788"
}

# Submit payload via PUT
# Note that the request uses "Content-Type: application/octet-stream" to describe the
# public key in PEM format.
curl -vv -X PUT -H "X-Auth-Token: $TOKEN" \
-H 'Accept: application/json' \
-H 'Content-Type: application/octet-stream' \
--data-binary @public.pem \
http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb

# Response
204 - No Content

# GET metadata
curl -vv -H "X-Auth-Token: $TOKEN" \
-H 'Accept: application/json' \
http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb |
python -m json.tool

# Response
# Note that this time content_types lists "application/octet-stream"
# because that is what the user provided in the PUT 
{
    "algorithm": "RSA",
    "bit_length": null,
    "content_types": {
        "default": "application/octet-stream"
    },
    "created": "2015-04-09T20:37:42.764788",
    "creator_id": "3a7e3d2421384f56a8fb6cf082a8efab",
    "expiration": null,
    "mode": null,
    "name": "RSA Public Key",
    "secret_ref": "http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb",
    "secret_type": "public",
    "status": "ACTIVE",
    "updated": "2015-04-09T20:39:47.583588"
}

# Retrieve payload
# Note that the default content-type is used in the Accept header.
curl -vv -H "X-Auth-Token: $TOKEN" \
-H 'Accept: application/octet-stream' \
-o retrieved_public.pem \
http://localhost:9311/v1/secrets/3c9c2973-7c39-48ee-9e01-899de2f4dafb/payload

# Response
200 OK 

# The retrieved PEM file should be identical to the original PEM file
diff public.pem retrieved_public.pem # shows no difference
