FROM       ubuntu:16.04
MAINTAINER delsponn@gmail.com

# Environment
ENV user=prob

# add user && config
RUN useradd -m -d /home/$user/ -s /bin/bash $user
RUN echo "$user     hard    nproc   20" >> /etc/security/limits.conf

# update && install xinetd
RUN apt-get update
RUN apt-get install -y xinetd python

# COPY
COPY ./meltdown_tester /home/$user/meltdown_tester
COPY ./flag /home/$user/flag
COPY ./xinetd_conf /etc/xinetd.d/xinetd_conf

# apply permissions
RUN chown -R root:$user /home/$user
RUN chmod -R 750 /home/$user
RUN chmod 440 /home/$user/flag

# EXPOSE
EXPOSE 1818

# CMD
CMD ["/usr/sbin/xinetd", "-d"]
