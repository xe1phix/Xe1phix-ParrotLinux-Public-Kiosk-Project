

## ------------------------------------------ ##
##                  +-------+
##                  |Root CA|
##                  +-------+
##                      |
##                      |
##              +---------------+
##              | Gitlab Sub-CA |
##              +---------------+
##                |     |     |
##                |     |     |
##              USER1 USER2 USERn
## ------------------------------------------ ##



###-==============================================================================-##
###                           [+] Connection Diagram
###-==============================================================================-##

```
+--------------+   Local Socket   +------------+   SSL Mutual Authentication   +----+
|Gitlab Service|------------------|Nginx Server|-------------------------------|User|
+--------------+                  +------------+                               +----+
```

