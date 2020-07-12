# dew - DeWildcarding dns resolver

## Compile
```
go build dew

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

[x] resolve
[x] retry
[x] dewildcard
[ ] verify
[ } exclude bad resolvers
[x] print
