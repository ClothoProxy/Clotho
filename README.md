# Clotho

A minimal AWS sigv4 verification library that can be used as an external authoriser with your favourite proxy.
Clotho aims to be fast and secure.

Why do you need Clotho ?

1. Security. It's a way of enforcing AWS account,region or service access to public endpoints that don't support VPC endpoints or for resources that don't support policies. Other solutions don't support the AWS API.
2. Cost. You don't have to pay for AWS Private Endpoints - if you only care for cross account attacks. You can use a proxy of your choosing and authorise requests.

Clotho expects a [config.yaml](./examples/config.yaml.example) file as an allowlist for allowed accounts, regions, and services.
Wildcards are supported using "*".


The current implementation derives the AWS Account ID offline using the technique described in [a short note on AWS KEY ID by Tal Be'ery](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489). Currently doesn't work with keys issued before ~2019, but maybe that's a good thing.

You can find docs at [docs.rs](https://docs.rs/Clotho/latest)

## What's included

The library is published as a crate and should be able to cross build it targeting aarch64 using cross.


Run the example
`cargo run  --example examplecli -- --config examples/config.yaml.example --credential AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request`

The binary folder contains
- A simple binary for use with squid [squid.rs](./src/bin/squid.rs)
- A very basic ICAP server - also for use with squid - [squid-icap.rs](./src/bin/squid-icap.rs)

You should be able to target other architectures with `cross`, e.g.
`cross build --target aarch64-unknown-linux-gnu --bin ...`



## Cost Savings

A back-of-the-envelope calculation comparing VPC Endpoints and Clotho, with the following assumptions:

- Running on us-east-1
- Everything runs across x3 AZs
- There is no intra region traffic when reaching Clotho instances 
- There are no egress costs for reaching out to AWS Services in the same region - [Reference](https://aws.amazon.com/blogs/architecture/overview-of-data-transfer-costs-for-common-architectures/)
- Clotho runs on graviton and the pricing is on-demand

| Traffic | VPCE Count | VPCE Price | Clotho Price | Clotho instance type|
| :-- | :-- |:--: | :--: | :-- |
|  1 TB   | 10                 |  $226    | $9.072  | t4g x3 |
| 1 TB    | 20                 |  $433   | $9.072 | t4g x3 |
| 10 TB   | 10                 |  $316  | $83.16  | c6gd x3 |
| 10 TB   | 20                 |  $532 | $83.16   | c6gd x3 |
| 100 TB  | 10                 |  $1216 | $1078.27 | c7gn.2xlarge x3 |
| 100 TB  | 20                 |  $1432 | $1078.27 | c7gn.2xlarge x3 |

With Clotho you pay _only_ for the compute cost.
The vertical scale up calculation happens to accomodate for higher bursts.
A VPC Endpoint can burst to 100 Gbit/s with sustained 10Gbit/s.

A t4g instance would cater for up to 5 Gbit/s, and a c7gn.2xlarge up to 50Gbit/s . Figures taken from [ec2instances.info](https://instances.vantage.sh/?filter=graviton)


### FAQ
- Why not [AWS Management Console Private Access](https://docs.aws.amazon.com/awsconsolehelpdocs/latest/gsg/console-private-access.html) ?

It doesn't support API access, only console access.

### Roadmap
- [ ] Potentially fallback to calling `sts get-caller-identity`
- [ ] Add capabilities for web console access filtering
- [ ] Add examples/binaries for more proxies, e.g. Envoy
- [ ] Convert this list to issues
