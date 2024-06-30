# Nginx TLS SNI routing, based on subdomain pattern
Nginx can be configured to route to a backend, based on the server's domain name, which is included in the SSL/TLS handshake (Server Name Indication, SNI).  
This works for http upstream servers, but also for other protocols, that can be secured with TLS.  

## prerequisites
 - at least nginx 1.15.9 to use variables in ssl_certificate and ssl_certificate_key.
 - check `nginx -V` for the following:  
   ```bash
   ...
   TLS SNI support enabled
   ...
   --with-stream_ssl_module 
   --with-stream_ssl_preread_module
   ```

It works well with the `nginx:1.15.9-alpine` docker image.

## non terminating, TLS pass through
Pass the TLS stream to an upstream server, based on the domain name from TLS SNI field. This does not terminate TLS.  
The upstream server can serve HTTPS or other TLS secured TCP responses.
```nginx
stream {  

  map $ssl_preread_server_name $targetBackend {
    ab.mydomain.com  upstream1.example.com:443;
    xy.mydomain.com  upstream2.example.com:443;
  }   
 
  server {
    listen 443; 
        
    proxy_connect_timeout 1s;
    proxy_timeout 3s;
    resolver 1.1.1.1;
    
    proxy_pass $targetBackend;       
    ssl_preread on;
  }
}
```

## terminating TLS, forward TCP
Terminate TLS and forward the plain TCP to the upstream server.
```nginx
stream {  

  map $ssl_server_name $targetBackend {
    ab.mydomain.com  upstream1.example.com:443;
    xy.mydomain.com  upstream2.example.com:443;
  }

  map $ssl_server_name $targetCert {
    ab.mydomain.com /certs/server-cert1.pem;
    xy.mydomain.com /certs/server-cert2.pem;
  }

  map $ssl_server_name $targetCertKey {
    ab.mydomain.com /certs/server-key1.pem;
    xy.mydomain.com /certs/server-key2.pem;
  }
  
  server {
    listen 443 ssl; 
    ssl_protocols       TLSv1.2;
    ssl_certificate     $targetCert;
    ssl_certificate_key $targetCertKey;
        
    proxy_connect_timeout 1s;
    proxy_timeout 3s;
    resolver 1.1.1.1;
      
    proxy_pass $targetBackend;
  } 
}

```

## Choose upstream based on domain pattern
The domain name can be matched by a regex pattern, and extracted to variables. See [regex_names](http://nginx.org/en/docs/http/server_names.html#regex_names).  
This can be used to choose a backend/upstream based on the pattern of a (sub)domain. This is inspired by [robszumski/k8s-service-proxy](https://github.com/robszumski/k8s-service-proxy).

The following configuration extracts a subdomain into variables and uses them to create the upstream server name.
```nginx
stream {  

  map $ssl_preread_server_name $targetBackend {
    ~^(?<app>.+)-(?<namespace>.+).mydomain.com$ $app-public.$namespace.example.com:8080;
  }
  ...
}
```

Your Nginx should be reachable over the wildcard subdomain `*.mydomain.com`.  
A request to `shop-staging.mydomain.com` will be forwarded to `shop-public.staging.example.com:8080`.  

### K8s service exposing by pattern 
In Kubernetes, you can use this to expose all services with a specific name pattern.  
This configuration exposes all service which names end with `-public`.  
A request to `shop-staging-9999.mydomain.com` will be forwarded to `shop-public` in the namespace `staging` on port `9999`.    
You will also need to update the resolver, see below.  

```nginx
stream {  

  map $ssl_preread_server_name $targetBackend {
    ~^(?<service>.+)-(?<namespace>.+)-(?<port>.+).mydomain.com$ $service-public.$namespace.svc.cluster.local:$port;
  }
  
  server {
    ...
    resolver kube-dns.kube-system.svc.cluster.local;
    ...
  }
}
```