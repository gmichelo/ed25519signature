# ed25519signature
Sign documents with ed25519 signature algorithm

## Usage

```
ed25519signature <command> <args>
```

Possible commands and respective arguments:

| Command   |   Arguments       |               |           |
|--------|----------------------|---------------|-----------|
| sign   | private-key-file     | file-to-sign              |
| verify | public-key-file      | file-to-check | signature |
| gen    | private-key-filename | public-key-filename       |

## Examples

How to generate a private/public keys pair, sign a document and finally validate it.

Generate the keys pair:
```
./ed25519signature gen key.pem pub.pem
```

Sign the main.go file:
```
./ed25519signature sign key.pem main.go
```

Output:
> Signature: 68561aec4d523f98c59dea6207ccf584ee344afcafbb50311bac5195399e6647607a42fcd0b9b377b5e8e68a5e264d3aae02aff9c06d4157edd3968806e7600f

Verify the signature with public key:
```
./ed25519signature verify pub.pem main.go 68561aec4d523f98c59dea6207ccf584ee344afcafbb50311bac5195399e6647607a42fcd0b9b377b5e8e68a5e264d3aae02aff9c06d4157edd3968806e7600f
```

Output:
> Valid signature

If we try to trick and pass a different signature we will get the following output and command exists with error state:
```
./ed25519signature verify pub.pem main.go 84cac10ed8217fac34811fac2f972b495721848842209454142e666a6acfae58c2cfc651b0d60f4f1e6e6af056760d7e83f2784b7cdd143d3534ccb1e0f9900d
```

Output:
> Invalid signature