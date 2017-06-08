# rpi-ipcheck: ipcheck.py Docker image for Raspberry Pi

<img src="images/rpi-ipcheck.png" width="300px" alt="rpi-ipcheck logo" />

## About

This [Docker](https://www.docker.com/) image is based on [Alpine Linux](http://www.alpinelinux.org/) Hypriot [image](https://hub.docker.com/r/hypriot/rpi-alpine-scratch/) for Raspberry Pi and embeds only essential packages to run ipcheck.py script.


[ipcheck.py](http://ipcheck.sourceforge.net/) is a Python script to register your dynamic IP address using the NIC V2.0 protocol.

## History

17/04/2016: v1.0.0 (First release)

## Usage

### Pull image from Docker Hub

First pull the image from the Docker registry with the following command : 

```bash
$ docker pull adzero/rpi-ipcheck:latest
```


### Helper script

The entrypoint of the image is a custom helper script *`rpi-ipcheck`* that handles necessary operations : 

```
rpi-ipcheck [-h] [-c] [-s [-p h|m] [-v 1-23|1-59]] [-e] [-r]

        -h : display this help
        -c : download ipcheck.py default configuration file and save it to '/etc/ipcheck/ipcheck.default.conf'
        -s : schedule ipcheck.py execution
        -p : set execution period to hours (h) or minutes (m) (-s option is mandatory to use -p)
             default value is 'h'
        -v : set period value (-s option is mandatory to use -v)
             valid value range is 1-23 (default is 1) for hour period and 1-59 for minute period (default is 5)
        -e : execute ipcheck.py with configuration file options
        -r : run the scheduler (schedule should exist or use -s option)
```

#### Use in image

To make a container based on this image work properly, you need to **use at least the following options** : 

+ `-s` to create the crontab schedule
+ `-r` to run the cron daemon 

### Create/Run container

Once image has been pulled, create or run your container with either the [create](https://docs.docker.com/engine/reference/commandline/create/) or the [run](https://docs.docker.com/engine/reference/commandline/run/) command. 

To access configuration file, a Docker host directory (*`/host/configuration/dir`*) must be mounted as the container configuration directory (*`/etc/ipcheck`*).   

Create example :
```bash
$ docker create -v /host/configuration/dir:/etc/ipcheck --name my-container adzero/rpi-ipcheck:latest -s -r 
```

Run example :
```bash
$ docker run -v /host/configuration/dir:/etc/ipcheck --name my-container adzero/rpi-ipcheck:latest -s -r 
```

#### Logs and output files

*`-v /host/logs/dir:/var/ipcheck`* can be used to store logs and ipcheck.py output files outside of the container. *`/host/logs/dir`* is the path on the Docker host where these files will be written.

#### Restart after failure

To ensure the container restarts after a failure, you can use the `--restart` option of the `create` or the `run` command : 

```bash
$ docker create -t -v /host/configuration/dir:/etc/ipcheck --restart:unless-stopped --name my-container adzero/rpi-ipcheck:latest
```

### Container start

Once your container is created, you can start it and check the logs : 

```bash
$ docker start my-container
my-container
$ docker logs -f my-container
```

If your configuration file exists (use `-c` helper script option to download default configuration file) and is valid you should see something as :

```
RPI-IPCHECK (2016-04-17 18:37:15)
RPI-IPCHECK: Setting rpi-ipcheck crontab entry.
RPI-IPCHECK: Configuration file found at '/etc/ipcheck/ipcheck.conf'.
RPI-IPCHECK: Invoking ipcheck.py for the first time
ipcheck/0.251
ipcheck.py: Sun Apr 10 21:30:01 2016
ipcheck.py: opt_directory set to /var/ipcheck/
ipcheck.py: opt_https_only set to '1'
ipcheck.py: opt_custom set
ipcheck.py: opt_makedat set
ipcheck.py: opt_username = user
ipcheck.py: opt_password = ************
ipcheck.py: opt_hostnames = domain.com
ipcheck.py: PWD = /root
ipcheck.py: Datfile = /var/ipcheck/ipcheck.dat
ipcheck.py: Errfile = /var/ipcheck/ipcheck.err
ipcheck.py: Waitfile = /var/ipcheck/ipcheck.wait
ipcheck.py: Htmlfile = /var/ipcheck/ipcheck.html
ipcheck.py: Tempfile = /var/ipcheck/ipcheck.tmp
ipcheck.py: web based ip detection for localip
ipcheck.py: Trying URL http://checkip.dyndns.org
ipcheck.py: webip.out file created
ipcheck.py: webip detected = XXX.XXX.XXX.XXX
ipcheck.py: DNS lookups to create data file.
ipcheck.py: Good, no ipcheck.dat file found.
ipcheck.py: ip1 looking up domain.com
ipcheck.py: result: 'domain.com'['domain.com']['XXX.XXX.XXX.XXX']
ipcheck.py: ip1 = XXX.XXX.XXX.XXX
ipcheck.py: Writing the new dat file.
ipcheck.py: Good, filehosts and hostnames are the same.
ipcheck.py: Good, no ipcheck.err file.
ipcheck.py: Good, no ipcheck.wait file.
ipcheck.py: Checking hosts in file vs command line.
ipcheck.py: The database matches local address.  No hosts update.
```

Otherwise, follow instructions in logs to fix any problem. 

## Build Docker image from source (for testing, collaboration or customization)

### Clone git repository

```bash
$ git clone https://github.com/adzero/rpi-ipcheck.git
```

### Build Docker image

```bash
$ docker build -t my-rpi-ipcheck:test .
```
