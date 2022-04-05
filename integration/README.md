# Test Script For go-cti
Documentation on testing for developers

## Getting Started
```terminal
$ pip install -r requirements.txt
```

## Run test
Use `127.0.0.1:1325` and `127.0.0.1:1326` to diff the server mode between the latest tag and your working branch.

If you have prepared the two addresses yourself, you can use the following Python script.
```terminal
$ python diff_server_mode.py --help
usage: diff_server_mode.py [-h] [--sample_rate SAMPLE_RATE] [--debug | --no-debug] {cves,multi-cves}

positional arguments:
  {cves,multi-cves}     Specify the mode to test.

optional arguments:
  -h, --help            show this help message and exit
  --sample_rate SAMPLE_RATE
                        Adjust the rate of data used for testing (len(test_data) * sample_rate)
  --debug, --no-debug   print debug message
```

[GNUmakefile](../GNUmakefile) has some tasks for testing.  
Please run it in the top directory of the go-cti repository.

- build-integration: create the go-cti binaries needed for testing
- clean-integration: delete the go-cti process, binary, and docker container used in the test
- fetch-rdb: fetch data for RDB for testing
- fetch-redis: fetch data for Redis for testing
- diff-cveid: Run tests for CVE ID in server mode
- diff-server-rdb: take the result difference of server mode using RDB
- diff-server-redis: take the result difference of server mode using Redis
- diff-server-rdb-redis: take the difference in server mode results between RDB and Redis
