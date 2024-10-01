# Pre-requisite

1. Change directory to the `lily-pqc` executable location
2. Ensure the `lily-pqc` executable can be executed

    ```
    $ chmod +x lily-pqc
    ```

# Server

## How to create PQC private key and certificate

Use the command below to create the PQC private key and certificate:
```
$ ./lily-pqc gen-pqc --output-certificate-file=/path/to/output/cert.crt --private-key-file=/path/to/output/private.key --algo-name=p521_dilithium5
```

- Modify the `--output-certificate-file=/path/to/output/cert.crt` to the desired output file path. Ensure that the specified output file does not already exist.
- Modify the `--private-key-file=/path/to/output/private.key` to the desired output file path. Ensure that the specified output file does not already exist.
- List of supported `--algo-name`:

    ```
    dilithium2
    p256_dilithium2
    rsa3072_dilithium2
    dilithium3
    p384_dilithium3
    dilithium5
    p521_dilithium5
    mldsa44
    p256_mldsa44
    rsa3072_mldsa44
    mldsa44_pss2048
    mldsa44_rsa2048
    mldsa44_ed25519
    mldsa44_p256
    mldsa44_bp256
    mldsa65
    p384_mldsa65
    mldsa65_pss3072
    mldsa65_rsa3072
    mldsa65_p256
    mldsa65_bp256
    mldsa65_ed25519
    mldsa87
    p521_mldsa87
    mldsa87_p384
    mldsa87_bp384
    mldsa87_ed448
    falcon512
    p256_falcon512
    rsa3072_falcon512
    falconpadded512
    p256_falconpadded512
    rsa3072_falconpadded512
    falcon1024
    p521_falcon1024
    falconpadded1024
    p521_falconpadded1024
    sphincssha2128fsimple
    p256_sphincssha2128fsimple
    rsa3072_sphincssha2128fsimple
    sphincssha2128ssimple
    p256_sphincssha2128ssimple
    rsa3072_sphincssha2128ssimple
    sphincssha2192fsimple
    p384_sphincssha2192fsimple
    sphincsshake128fsimple
    p256_sphincsshake128fsimple
    rsa3072_sphincsshake128fsimple
    mayo1
    p256_mayo1
    mayo2
    p256_mayo2
    mayo3
    p384_mayo3
    mayo5
    p521_mayo5
    ```

## How to run the server

Use the command below to run the server:

```
$ ./lily-pqc server-run --certificate-file=/path/to/input/cert.crt --private-key-file=/path/to/input/private.key --port=7004
```

- Change the `--certificate-file=/path/to/input/cert.crt` to the intended input certificate file. Classical and PQC certificate is allowed.
- Change the `--private-key-file=/path/to/input/private.key` to the intended input file. Classical and PQC private key is allowed.
- The certificate must be produced by the given private key
- The port can be any available (unused) port
- On certain operating systems, you may need to enable port access through the firewall

If the server runs successfully, the terminal will display:

```
[v] Listening to port 7004...
```

Keep the terminal open to ensure the server continues running.

## HTTP Response

The server will return the message body received from the client as the response.

## Server log generation and data recording

After the client is executed, the server will generate a CSV file containing details about the handshake duration (in µs), data received (in bytes), time taken to receive data (in µs), data sent (in bytes), and time taken to send data (in µs). The log will be saved in the current working directory with the filename format **YYYY-mm-dd_HH:MM:SS_log_server.csv**.

### CSV log sample

```
hs_duration_us;recv_size;recv_duration_us;write_size;write_duration_us
8407;83;43;117;21
4147;83;7;117;9
4051;83;6;117;8
4110;83;6;117;8
4046;83;6;117;8
4097;83;7;117;9
4087;83;6;117;8
4042;83;5;117;7
4005;83;6;117;7
...
```

## Server encapsulation record
For each handshake performed, the server will execute the key encapsulation function to handle key exchange within the TLS mechanism. The execution time of the encapsulation will be logged in the file **log_server_oqsencaps_us.csv**. This file is continuously appended, so please manually clear it before restarting the server to prevent leftover data from previous runs.

### CSV log sample
```
14
14
14
13
14
14
14
14
19
16
...
```

## Client certificate sign record
For each handshake performed, the server will execute the certificate sign function to sign the handshake data in TLS mechanism. The execution time of the certificate signing will be logged in the file **log_server_oqssign_us.csv**. This file is continuously appended, so please manually clear it before restarting the server to prevent leftover data from previous runs.

### CSV log sample
```
14
14
14
13
14
14
14
14
19
16
...
```

# Client

## How to run the client

Use the command below to run the client:

```
$ ./lily-pqc client-run --server-host=192.168.1.2 --server-port=7004 --concurrent-user=4 --tls-group=p256_kyber512 --data-length=100
```

- Change the `--server-host=192.168.1.2` to the actual server host
- Change the `--server-host=7004` to the actual server port
- Concurrency testing evaluates how well a `lily-pqc` server handles multiple users simultaneously performing the same actions. This process, also referred to as multi-user testing, assesses the server's ability to manage concurrent users. To adjust the number of users, modify the `--concurrent-user=4` flag to the desired level of concurrency.
- Modify the `--data-length=100` to reflect the expected size (in bytes) of the auto-generated dummy message body that will be sent to the server
- List of supported `--tls-group`:

    ```
    frodo640aes
    p256_frodo640aes
    x25519_frodo640aes
    frodo640shake
    p256_frodo640shake
    x25519_frodo640shake
    frodo976aes
    p384_frodo976aes
    x448_frodo976aes
    frodo976shake
    p384_frodo976shake
    x448_frodo976shake
    frodo1344aes
    p521_frodo1344aes
    frodo1344shake
    p521_frodo1344shake
    kyber512
    p256_kyber512
    x25519_kyber512
    kyber768
    p384_kyber768
    x448_kyber768
    x25519_kyber768
    p256_kyber768
    kyber1024
    p521_kyber1024
    mlkem512
    p256_mlkem512
    x25519_mlkem512
    mlkem768
    p384_mlkem768
    x448_mlkem768
    x25519_mlkem768
    p256_mlkem768
    mlkem1024
    p521_mlkem1024
    p384_mlkem1024
    bikel1
    p256_bikel1
    x25519_bikel1
    bikel3
    p384_bikel3
    x448_bikel3
    bikel5
    p521_bikel5
    hqc128
    p256_hqc128
    x25519_hqc128
    hqc192
    p384_hqc192
    x448_hqc192
    hqc256
    p521_hqc256
    ```

If the client runs successfully, the terminal will display:

```
[v] All users is active and testing the server!
[-] Successful Request: 3890 | Failed Request: 0 | TPS : 778.00 req/s
[-] Successful Request: 7808 | Failed Request: 0 | TPS : 780.80 req/s
[-] Successful Request: 11750 | Failed Request: 0 | TPS : 783.33 req/s
[-] Successful Request: 15708 | Failed Request: 0 | TPS : 785.40 req/s
[-] Successful Request: 19666 | Failed Request: 0 | TPS : 786.64 req/s
[-] Successful Request: 23598 | Failed Request: 0 | TPS : 786.60 req/s
[-] Successful Request: 27541 | Failed Request: 0 | TPS : 786.89 req/s
[-] Successful Request: 31506 | Failed Request: 0 | TPS : 787.65 req/s
...
```

## Client log generation and data recording

After the client is executed, it will generate a CSV file containing details about the handshake duration (in µs), data received (in bytes), time taken to receive data (in µs), data sent (in bytes), and time taken to send data (in µs). The log will be saved in the current working directory with the filename format **YYYY-mm-dd_HH:MM:SS_log_client.csv**.

### CSV log sample

```
hs_duration_us;write_size;write_duration_us;recv_size;recv_duration_us
8420;83;25;117;123
4136;83;5;117;113
4058;83;7;117;98
4110;83;5;117;91
4043;83;7;117;88
4060;83;6;117;120
4076;83;5;117;104
4033;83;5;117;84
3978;83;5;117;95
...
```

## Client decapsulation record
For each handshake performed, the client will execute the key decapsulation function to handle key exchange within the TLS mechanism. The execution time of the decapsulation will be logged in the file **log_client_oqsdecaps_us.csv**. This file is continuously appended, so please manually clear it before restarting the client to prevent leftover data from previous runs.

### CSV log sample
```
14
14
14
13
14
14
14
14
19
16
...
```

## Client key generation record
For each handshake performed, the client will execute the key generation function for key exchange within the TLS mechanism. The execution time of the key generation will be logged in the file **log_client_oqskeygen_us.csv**. This file is continuously appended, so please manually clear it before restarting the client to prevent leftover data from previous runs.

### CSV log sample
```
14
14
14
13
14
14
14
14
19
16
...
```

## Client certificate verify record
For each handshake performed, the client will execute the certificate verify function to verify the signature in TLS mechanism. The execution time of the certificate verification will be logged in the file **log_client_oqsverify_us.csv**. This file is continuously appended, so please manually clear it before restarting the client to prevent leftover data from previous runs.

### CSV log sample
```
14
14
14
13
14
14
14
14
19
16
...
```

# Performance notes

- Due to the need to write logs to a file, there will be some noticeable overhead compared to running without log writing during each server and client connection. This is because file writing is resource-intensive and requires synchronization.
