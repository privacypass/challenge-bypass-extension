# Privacy Pass configuration

Privacy Pass uses cryptographic tokens to bypass internet challenges from
certain providers. In this doc, we discuss the configuration file that Privacy
Pass uses for interpreting when tokens should be sent for signing/redemption.
See config.js for an example configuration (exampleConfig) describing the
correct format of the JSON struct.

## config.js

Holds the various configurations as JavaScript JSON structs for the providers
that Privacy Pass interacts with. Currently, only the Cloudflare config is
active. There is an example config, there is also an in progress config for the
CAPTCHA provider FunCAPTCHA. In the following we will highlight how each config
field is used.

### config["id"]

A unique identifier highlighting which config is used. Currently cfConfig.id =
1, all other configs must be added with unique "id" values.

### config["sign"]

A bool dictating whether Privacy Pass should send tokens for signing. 

### config["redeem"]

A bool dictating whether Privacy Pass should send tokens for redemption.

### config["sign-reload"]

A bool dictating whether the page should be reloaded after tokens are
successfully signed

### config["sign-resp-format"]

Format of the response (as a string) to a signing request. Currently, support
"string" or "json". When "string" is used, expect the signed tokens to be
included (base-64 encoded) in the HTTP response body in the form `signatures= ||
<signed-tokens> || <Batch-DLEQ-Resp>`. When "json" is used, expect the signed
tokens to be included (base-64 encoded) as a JSON struct with key: "signatures"
and value `<signed-tokens> || <Batch-DLEQ-Resp>`.

### config["max-spends"]

The integer number of tokens that should be redeemed per host in each
interaction. This prevents Privacy Pass from repeatedly spending tokens for the
same host (if some unknown issues occur, for example).

### config["max-tokens"]

The integer number of tokens that should be held by Privacy Pass at any one
time.

### config["tokens-per-request"]

The integer number of tokens that should be sent with each signing request. For
Cloudflare, there is also a server-side upper bound of 100 tokens for each
signing request. We recommend that this is enforced to prevent unlimited numbers
of tokens being signed.

### config["var-reset"]

A bool dictating whether the set of variables holding previous redemption
information should be reset (see resetVars() in background.js). We recommend
this is set to true, since these variables prevent tokens from being spent in
the future.

### config["var-reset-ms"]

The time intervals (ms) by which the variables from above are reset.

### config["commitments"]

Hex-encoded elliptic curve commitment values for verifying DLEQ proofs. These
essentially amount to public keys issued by the provider. The values of "G" and
"H" held in config["commitments"]["dev"] should be used for development
purposes. Those held in config["commitments"]["prod"] should be used in the
production environment.

### config["spending-restrictions"]

A JSON struct of restrictions for redeeming tokens

#### config["spending-restrictions"]["status-code"]

An integer corresponding to the status code returned by the server. This HTTP
status code is checked before a redemption is initiated, for Cloudflare this
value is set to 403. That is, token redemptions can only occur after a HTTP
response with status code 403 is received.

#### config["spending-restrictions"]["max-redirects"]

An integer dictating the number of times that tokens should be spent after
requests have been redirected. That is, consider a HTTP response that Privacy
Pass deems suitable to initiate a redemption. This number indicates how may
redemption HTTP requests will be tolerated where the response from the server
results in HTTP redirection.

#### config["spending-restrictions"]["new-tabs"]

An array of strings indicating that the tab that is open corresponds to a new
tab (and thus token redemption should not occur).

#### config["spending-restrictions"]["bad-navigation"]

An array of strings corresponding to chrome.webNavigation methods that indicate
navigation types where tokens should not be redeemed. In the case of Cloudflare,
this is limited to `auto_subframe` navigations that are not used for Cloudflare
CAPTCHAs.

#### config["spending-restrictions"]["bad-transition"]

Similar to above, except for transition types. For Cloudflare, we rule out
redemption requests when `server_redirect` is the transition type.

#### config["spending-restrictions"]["valid-redirects"]

An array of strings indicating the URL redirections that are tolerated when
tokens are being redeemed. For example, redemptions that upgrade HTTP
connections to HTTPS connections.

#### config["spending-restrictions"]["valid-transitions"]

An array of strings indicating the transition types that are definitely valid,
when considering whether redemption requests should be sanctioned.

#### config["spending-action"]["urls"]

URLs that activate WebRequest listeners, "`<all_urls>`" corresponds to matching
all possible URLs.

#### config["spending-action"]["redeem-method"]

A string that determines the method that token redemptions are handled.
Currently the only methods that is supported is `"reload"`. This means that
tokens are redeemed by reloading the page and appending tokens to the subsequent
HTTP request.

#### config["spending-action"]["header-name"]

The name of the header that contains a token for redemption.

#### config["cookies"]["check-cookies"]

A boolean value that determines cookies should be checked before tokens are sent
for redemption. That is, a token is not redeemed if the browser has a clearance
cookie for the URL that redemption occurring for.

#### config["cookies"]["clearance-cookie"]

A string that specifies the specific name of the type of clearance cookie used
by the provider. In the case of Cloudflare, this is `"cf_clearance"`.

#### config["captcha-domain"]

A string specifying a domain where users can obtain signed tokens by solving a
challenge/CAPTCHA. This is helpful to allow users to build up initial stockpiles
of tokens before they browse.

#### config["error-codes"]["verify-error"]

String error code that the server returns if token redemption fails due to a
signature verification error.

#### config["error-codes"]["connection-error"]

String error code that the server returns if an internal connection error occurs
server-side.

#### config["h2c-params"]

A JSON struct of parameters for the curve setting that the client uses. These
settings are sent to the server with all redemption requests.

#### config["h2c-params"]["curve"]

A string that defines the elliptic curve that is being used for mapping tokens
to. Currently we only support the NIST curve P256, this is represented by the
string "p256".

#### config["h2c-params"]["hash"]

The actual hash function that is used for hashing bytes to the base field of the
curve. Currently we only support the usage of the SHA256 hash function, using
the string "sha256".

#### config["h2c-params"]["method"]

The hash-to-curve method that is used for moving field elements to curve points.
If it is set to "increment" then we use the hash-and-increment method
that will be deprecated moving forward. If it is set to "swu", then we use the
affine version of the SWU algorithm implemented in h2c.js (see
[HASH_TO_CURVE.md](docs/HASH_TO_CURVE.md) for a description of the algorithm in
full).

#### config["send-h2c-params"]

A boolean that determines whether the contents of config["h2c-params"] should
actually be sent to the server.