# bananaphone - SSH Credential Plumbing for Docker Builds

Some silly scripts for a silly problem.


- Tried a variety of methods but all fail by persisting the key contents in image.

- But where there is a will thre is a way!

# Docker + SSH Prototype

**I just want to see the demo!**

```
make keyfile=<path-to-keyfile>
make test
```

**Simple usage:** `nc localhost $(bananaphone -f README.md)`


**How it Works**

- Similar to many of the other 'credserver' solutions but there had to
  be a simpler way than setting up a whole service to get a file into
  a docker build context without persisting it to the image.

- Give the docker build context to the host's network at build time
  and use the bananaphone daemon to listen on a random ephemeral port
  and pass the contents of a keyfile into a build!

- The wrapper script `exec-with-identity` manages writing the keyfile
  to tmpfs and setting up the ssh agent before executing the command.

- By design, tmpfs will not persist across restarts since it is a ram
  mounted filesystem. In the docker context, this means it will not persist
  after builds or container restarts.

- Granted this way is fragile due to some added complexity but it does
  not seem to persist the keyfile into the image filesystem or
  history.
