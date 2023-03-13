## Setting Up PAT in Local Machine.

```sh
 $ git clone https://github.com/armfazh/pat-app --branch devel_branch
cd pat-app
```


```sh
 $ make certs
 ```
 Make sure to follow the instructions in README for setting up certificates in your machine using mkcert.


In three terminals:
 - `make issuer`
 - `make origin`
 - `make attester`

Running Go client

```sh
$ ./pat-app fetch --origin origin.example:4568 --secret `cat client.secret` --attester attester.example:4569 --resource "/index.html" --token-type basic
```

When the client is run, it fetches the privacypass webpage from origin using 'basic' (Type 2) tokens. (We will use Type 2 tokens initially, so it must be explicitly specified in the command/URL)

A succesfull run looks like:

```sh
$ ./pat-app fetch --origin origin.example:4568 --secret `cat client.secret` --attester attester.example:4569 --resource "/index.html" --token-type basic
body was fetched!!
<!doctype
```

---

## Setting Up Chrome Extension

In a terminal:

```sh
$ git clone https://github.com/armfazh/challenge-bypass-extension --branch = declNetReq
$ nvm use 18 // it should work with Node v16+.
$ npm ci
$ npm run build
```

In Chrome:

1. Remove all extensions of privacy pass. current ext is v3.0.4.

1. We will install ext v4.1.0
which has **manifest v3 AND has no UI**.

1. Load the extension from the source code.

1. Open the Background Page & Devtools of a blank tab.

1. Navigate to https://origin.example:4568/?type=2
(Make sure the certificates from `mkcert` step work, otherwise cannot load https from localhost). As you can see, we must specify type=2.

1. The behaviour expected is that browser first receives a 401 error, which is catched by the extension and then a reload that brings the body of the privaypass website. *There could be some errors fetching other resources (.css files), but these are not served by the pat-app demo.
