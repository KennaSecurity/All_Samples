# Agent Container

This repository provides a way to run the [Kenna Agent](https://help.kennasecurity.com/hc/en-us/articles/360029047771-Setting-Up-the-Kenna-Agent) in a self-contained container allowing you to pass secrets in a secure method of your choosing.  The repository, as configured, stores variables in the agent.env file, which is passed to the system at run time.  The container is easily modified to pass these variables from any secure location. Information on passing variables in other ways can be found in the [Docker documentation](https://docs.docker.com/engine/reference/commandline/run/).

## Configure

Edit the ```kenna-agent.toml``` file using the information provided on [the setup page](https://help.kennasecurity.com/hc/en-us/articles/360029047771-Setting-Up-the-Kenna-Agent) replacing your secrets with global variables you store in agent.env

Add your secrets to the agent.env.

Edit the ```entrypoint.sh``` to include all needed secrets.

## Build

Build the container using the following command:
```docker build --pull --rm -f DockerFile -t agent:latest $PWD```

## RUN

Run the container using the following command:
```docker run --env-file="agent.env" agent```
