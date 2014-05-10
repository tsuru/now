# Tsuru Now

Yet another script to install tsuru and its dependencies.

These are some goals for this project:

* It should run without interaction and deliver a working environment;
* It shouldn't be a problem to run the script multiple times on the same machine;
* It should work on existing machines that might already have some components installed;
* It should allow parameters to install a single role:
    * API node
    * Docker node
    * Load balancer node
* A web UI to automatically run it on EC2 instances

## Running

Running the command below should already create a working tsuru environment:

```
curl -sL https://raw.github.com/tsuru/now/master/run.bash | bash -ue
```