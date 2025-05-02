# Everdeen Simulation Codebase

## Overview
This repository contains a portion of the code needed to reproduce the measurements presented in the Everdeen paper **(TODO: add link)**.
All measurements in the paper are fully reproducible, and the code has been organized across two separate repositories.
- **[WNB evaluation](https://github.com/netsec-ethz/everdeen-eval-wnb)**. It allows simulating A2A and WNB on Internet topologies and enables reproducing the measurements for Figures 3–6, Figures 9–13, and Table 3 from the paper.
- **[This repository](https://github.com/netsec-ethz/everdeen-eval-dosc)**. It allows evaluating DOSC’s robustness to volumetric DDoS attacks and enables reproducing the measurements for Figure 8 from the paper.

## Setup
#### The following tools need to be installed:
1. Golang: https://go.dev/
2. Everdeen simulator:
```
git clone https://github.com/netsec-ethz/everdeen-eval-dosc.git
cd everdeen-eval-dosc
go build ec2-test.go
```

#### The following Amazon EC2 configuration is required to run the evaluation:

Make sure that the EC2 region "Europe (Zurich)" is enabled and provide the following environment.

```
export AWS_ACCESS_KEY_ID='<AWS access key id with privileges for EC2 and VPC>'
export AWS_SECRET_ACCESS_KEY='<AWS access key secret>'
export AWS_SECURITY_GROUP_ID='<AWS security group id>'
export AWS_SUBNET_ID='<AWS subnet id>'
export SSH_ID='<AWS SSH key pair id>'
export SSH_SECRET_ID_FILE='<Path to AWS SSH private key file>'
```

The provided security group should at least allow inbound access as follows:
- Type: SSH, Source: 0.0.0.0
- Type: All traffic, Source: Same security group

#### The following reproduces Figure 8 (b) from the paper "Linux-based router with offset measurements using chrony":
```
./ec2-test setup
./ec2-test run
./ec2-test teardown
```

After a test run, open the evaluation plot at `logs/offsets.pdf`.

Note 1: The step `./ec2-test setup` will take approx. 5 to 10 minutes.

Note 2: To reproduce Figure 8 (a), add the flag `--mode scion` to the commands above.

Note 3: To show the state of all EC2 instances in the evaluation setup, execute `./ec2-test list`. Use this to make sure that all instances are in state `terminated` after tearing down the setup.

## Structure
#### The repository contains:
- `ec2-test.go`: The **code** to execute the measurements.
- `dist`: Required **dependencies** in source and binary form.
- `logs`: The execution **logs** collected during the experiments.
- `testnet`: The testbed **configuration**, corresponding to Figure 7 in the paper.
