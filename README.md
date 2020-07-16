# dew - DeWildcarding dns resolver

## Compile
```
make
```

## Usage

```
Usage of ./dew:
  -c int
    	Number of "threads" working, tune this for optimum performance. (default 20)
  -h	alias for -help
  -help
    	Prints help text
  -pw
    	Prints all found wildcard domains
  -r string
    	Optional but recommended resolvers file, newline separated resolver ips
  -v	Enables ip numbers printing to output
```


## Features

 - [x] resolve
 - [x] retry
 - [x] dewildcard
 - [x] verify (naive impelentation implemented)
 - [ ] exclude bad resolvers
 - [x] print

## TODO

Some servers returns NOERROR for missing A records
Some servers returns NXDOMAIN for missing A records
We should both look at Rcode and Answer section before disregardning a domain
