SciTokens Authorization Support for Xrootd
==========================================

This ACC (authorization) plugin for the Xrootd framework utilizes the [SciTokens
library](https://www.scitokens.org) to validate and extract authorization claims from
a SciToken passed during a transfer.

Configured appropriately, this allows the Xrootd server admin to delegate authorization
decisions for a subset of the namespace to an external issuer.  For example, this would
allow LIGO to decide the read/write authorizations for pieces of the LIGO namespace.

Loading the plugin in Xrootd
----------------------------

To load the plugin, add the following lines to your Xrootd configuration file:

```
ofs.authorize
ofs.authlib libXrdAccSciTokens.so
```

Restart the Xrootd service.  The SciTokens plugin in the `ofs.authlib` line additionally can take a
parameter to specify the configuration file:

```
ofs.authlib libXrdAccSciTokens.so config=/path/to/config/file
```

If not given, it defaults to `/etc/xrootd/scitokens.cfg`.  Restart the service for new settings to take effect.

SciTokens Configuration File
----------------------------

The SciTokens configuration file (default: `/etc/xrootd/scitokens.cfg`) specifies the recognized
issuers and maps them to the Xrootd namespace.  It uses the popular INI-format.  Here is an example
entry:

```
[Issuer OSG-Connect]

issuer = https://scitokens.org/osg-connect
base_path = /stash
map_subject = True
```

Each section name specifying a new issuer *MUST* be prefixed with `Issuer`.  Known attributes
are:

   - `issuer` (required): The URI of the token issuer; this must match the value of the corresponding claim int
      the token.
   - `base_path` (required): The path any token authorizations are relative to.
   - `map_subject` (optional): Defaults to `false`; if set to `true`, any contents of the `sub` claim will be copied
      into the Xrootd username.  When combined with the [xrootd-multiuser](https://github.com/bbockelm/xrootd-multiuser)
      plugin, this will allow the Xrootd daemon to write out files utilizing the Unix username specified by the VO
      in the token.  Except in narrow use cases, the default of `false` is sufficient.
