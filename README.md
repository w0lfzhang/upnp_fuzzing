A tool to fuzz the upnp protocol of ASUS routers.
And most of the code comes from miranda.

## Data Generating
Generating data aimed to the action's arguments. As far as I see the UPnP protocol, this is the most fuzzable point. And as if there is no proper point to fuzz.
So how to generate fuzzing data? This is the most important thing in fuzzing process. 
## Fuzzing
OK, nothing to say~ Just normal job
## Monitor
Adding a simple monitor is necessary, which can make sure whether the server is down or not.
## Exploit
Auto-exploit? No, that's bullshit! We must analyse the data that makes the server down manually.

Let's take a look at the upnp's services of the routers.