#=====================================================================
docker-compose -f docker-compose.json up #use JSON instead of YAML compose file
#=====================================================================
docker-compose -f ~/hello_world/docker-compose.yml build
docker-compose -f ~/hello_world/docker-compose.yml up -d
docker-compose ps # Lists containers.
docker-compose stop
docker-compose start # Starts existing containers for a service.
docker-compose stop # Stops running containers without removing them.
docker-compose pause # Pauses running containers of a service.
docker-compose unpause # Unpauses paused containers of a service
docker-compose up #Builds, (re)creates, starts, and attaches to containers for a service
docker-compose up -d #Create docker image and run container in the background
docker-compose down # Stops containers and removes containers, networks, volumes, and images created by up.
docker-compose down -v # tear down the containers and volumes
docker-compose --version
docker-compose ps
docker-compose images #List images used by the created containers
docker-compose stop
docker-compose run web
docker-compose down
	
docker-compose -f docker-compose-dev.yml up -d app1
docker-compose -f docker-compose-test-local.yml run --rm unit
docker-compose -f docker-compose-test-local.yml build app -> as an alternative, define build arguments inside a Docker Compose file
docker-compose build

docker-compose config

docker-compose -f docker-compose-test-local.yml up -d staging-dep
docker-compose -f docker-compose-test-local.yml ps
docker-compose -f docker-compose-test-local.yml run --rm staging
docker-compose -f docker-compose-test-local.yml down
docker-compose -f docker-compose-local.yml up -d registry
#=====================================================================
docker-compose logs
docker-compose logs -f initializer #track progress
docker-compose logs initializer | grep "Admin password:" #obtain admin credentials
#=====================================================================
docker-compose up -d #Create docker image and run container in the background
docker-compose exec kali /bin/bash #Create docker image and run container in the background
#=====================================================================
docker build -t kalicmd . --file=/vagrant/dockerfiles/kalilinux/toolkali
docker-compose --file /vagrant/dockerfiles/kalilinux/docker-compose.yml run kali-service
docker-compose --file /vagrant/dockerfiles/kalilinux/docker-compose.yml ps #Lists containers

cat docker-compose.yml
version: '3'
services:
  kali-service:
    image: "kalicmd"
    volumes:
      - /mnt/share-kali:/share
      - /mnt/share-kali/.bash_history:/root/.bash_history
#=====================================================================
docker-compose build --no-cache #Force the execution of each step/instruction in the Dockerfile
docker-compose build --no-cache && docker-compose up -d --force-recreate #t recreate all containers
docker build --pull --no-cache --tag myimage:version #force rebuilding of layers already available
#=====================================================================
#=====================================================================
WINDOWS
#=====================================================================
docker-compose version
#=====================================================================
#=====================================================================
#=====================================================================
#=====================================================================
#environment variable, non-default dockere file name
#docker-compose.yaml
version: '3.8'
services:
  myservice:
    build:
      context: .
      dockerfile: ./docker/Dockerfile.myservice
    image: myself/myservice
    env_file:
     - ./var.env
    environment:
     - VAR_C=C
     - VAR_D=D
    volumes:
     - $HOME/myfolder:/myfolder
    ports:
     - "5000:5000"

#=====================================================================
cat Dockerfile.test
cat docker-compose.test.yml
docker-compose -f ~/hello_world/docker-compose.test.yml -p ci build
docker-compose -f ~/hello_world/docker-compose.test.yml -p ci up -d
docker-compose -p ci stop
#=====================================================================
                  Docker Compose v2	          Docker compose v3
 Multi-host	      No	                        Yes                  
 Start services	  docker-compose up -d	      docker stack deploy --compose-file=docker-compose.yml  
 Scale service	  docker-compose scale =	    docker service scale =
 Shutdown	        docker-compose down	        docker stack rm

#=====================================================================
# docker-compose.yml
version: '3'

services:
  web:
    build: .
    # build from Dockerfile
    context: ./Path
    dockerfile: Dockerfile
    ports:
     - "5000:5000"
    volumes:
     - .:/code
  redis:
    image: redis
#=====================================================================
# Builds, (re)creates, starts, and attaches to containers for a service.
docker-compose up
# Stops containers and removes containers, networks, volumes, and images created by up.
docker-compose down
#=====================================================================
web:
  # build from Dockerfile
  build: .
#=====================================================================
  # build from custom Dockerfile
  build:
    context: ./dir
    dockerfile: Dockerfile.dev
#=====================================================================
  # build from image
  image: ubuntu
#=====================================================================
ports:
    - "3000"
    - "8000:80"  # guest:host
#=====================================================================
  # expose ports to linked services (not to host)
  expose: ["3000"]
#=====================================================================
# command to execute
  command: bundle exec thin -p 3000
  command: [bundle, exec, thin, -p, 3000]
#=====================================================================
  # override the entrypoint
  entrypoint: /app/start.sh
  entrypoint: [php, -d, vendor/bin/phpunit]
#=====================================================================
  volumes:
    - /var/lib/mysql
    - ./_data:/var/lib/mysql

version: '2'
  services:
    cms:
       image: <IMAGE>:<TAG>
       ports:
       - <LOCAL_PORT>:<CONTAINER_PORT>
       volumes:
       - <LOCAL_PATH>:<CONTAINER_PATH>
       
#=====================================================================
# join a pre-existing network
networks:
  default:
    external:
      name: frontend
#=====================================================================
# creates a custom network called `frontend`
networks:
  frontend:
#=====================================================================
  # makes the `db` service available as the hostname `database`
  # (implies depends_on)
  links:
    - db:database
    - redis
#=====================================================================
  # make sure `db` is alive before starting
  depends_on:
    - db
#=====================================================================
services:
  web:
    dns: 8.8.8.8
    dns:
      - 8.8.8.8
      - 8.8.4.4
