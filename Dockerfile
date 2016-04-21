FROM hypriot/rpi-alpine-scratch

LABEL	name="rpi-ipcheck" \
	description="ipcheck.py Docker image for Raspberry Pi" \
	version="1.0.0" \
	vendor="AdZero"

MAINTAINER AdZero (https://github.com/AdZero)

#Copy ipcheck.py files and scripts
COPY ipcheck /root/ipcheck/

#Misc. operations to update image and set files locations
RUN	mkdir -p /opt/ipcheck && \
	mkdir -p /etc/ipcheck && \
	mkdir -p /var/ipcheck && \
	mv /root/ipcheck/opt/* /opt/ipcheck && \
	rm -Rf /root/ipcheck && \
	chmod 500 /opt/ipcheck/*ipcheck && \
	apk update && \
	apk upgrade && \
	apk add bash && \ 
	apk add python && \
	apk add openssl &&\
	wget -O /opt/ipcheck/ipcheck.py https://sourceforge.net/projects/ipcheck/files/ipcheck.py/download && \
	wget -O /etc/ipcheck/ipcheck.default.conf https://sourceforge.net/projects/ipcheck/files/ipcheck.conf/download && \
        apk del openssl && \
        rm -rf /var/cache/apk/*

ENTRYPOINT ["/opt/ipcheck/rpi-ipcheck"]
