# dew - DeWildcarding dns resolver

## Compile
```
make
```

## Usage

```
Usage of ./dew:
  --help
    	Prints help text
  -c int
    	Number of "threads" working, tune this for optimum performance. (default 2)
  -cj int
    	Number of concurrent jobs (default 1000)
  -debug
    	Outputs debug information
  -dt duration
    	DNS Timeout in millisecods (default 1s)
  -h	alias for --help
  -mv int
    	Number of required verification dns requests (default 3)
  -r string
    	Optional but recommended resolvers file, newline separated resolver ips
  -v	Enables ip numbers printing to output
```


## Features

 - [x] resolve
 - [x] retry
 - [x] dewildcard
 - [x] verify (naive impelentation)
 - [ ] exclude bad resolvers
 - [x] print

## TODO

Some servers returns NOERROR for missing A records
Some servers returns NXDOMAIN for missing A records
We should both look at Rcode and Answer section before disregardning a domain
