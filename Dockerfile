FROM golang:1.6

# download the message-secure-send source, build it and install it
RUN go get github.com/dsblox/mss/... #force by changing this number 88

# set up some aliases useful in our development environment
RUN echo 'alias cd-mss="cd /go/src/github.com/dsblox/mss"' >> ~/.bashrc
RUN echo 'alias run-mss="cd-mss;gss"' >> ~/.bashrc
RUN echo 'alias make-mss="cd-mss;cd gss;go install;cd-mss"' >> ~/.bashrc

# CMD is only executed if another command is not specified on the docker run command
# so if container is run as a daemon then assume we are running the server
# but if container is run with -it and /bin/bash as the command then the server won't be started
# . and we can build and restart the server in a dev / test environment.
CMD gss -html /go/src/github.com/dsblox/mss/client -cert /go/src/github.com/dsblox/mss

# expose port 4000 for the API and the serving of client files
# note that we have a problem because the client app.js is hardcoded
# to talk to localhost:4000.  We need to somehow break out the client
# before this system is fully operational
EXPOSE 4000
