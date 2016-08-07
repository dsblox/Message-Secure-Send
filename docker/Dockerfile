FROM golang:1.6

# download the message-secure-send source, build it and install it
RUN go get github.com/dsblox/mss/...

# CMD is only executed if not opened as a shell with -it.  So if this docker
# container is run as a daemon then assume we are running the server
# TBD: how do we tell docker to expose ports 80 and 4000?
CMD gss -html /go/src/github.com/dsblox/mss/client -certs /go/src/github.com/dsblox/mss -port 4000

# expose port 4000 for the API and the serving of client files
# note that we have a problem because the client app.js is hardcoded
# to talk to localhost:4000.  We need to somehow break out the client
# before this system is fully operational
EXPOSE 4000
