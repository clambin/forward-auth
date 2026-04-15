# Identity Providers

## General

### Redirect URI
Setting up an identity provider involves setting up a redirect URI. This is the URL that the identity provider will redirect to after the user has authenticated.
For `forward-auth`, this must be set to `/api/auth/login`.

So, if `forward-auth` can be reached at `https://auth.example.com`, the redirect URI should be `https://auth.example.com/api/auth/login`.

## Providers

### Google

`forward-auth` uses Google's OpenID Connect to authenticate users. 

Head to https://console.developers.google.com and create a new project. Create new Credentials and select OAuth Client ID
with "web application" as its application type.

Give the credentials a name and define the authorized redirect URIs as per the section [Redirect URI](#redirect-uri).  
Register the application and note the Client ID and Client Secret.

Configure authn.provider to use oicd to authenticate users:

```yaml
authn:
  provider:
    type: oidc
    oidc:
      client_id: "<client_id>"
      client_secret: "<client_secret>"
      issuer_url: https://accounts.google.com
```

### GitHub

Since GitHub does not support OpenID Connect, `forward-auth` uses GitHub's OAuth2 API to authenticate users.

Head to https://github.com/settings/developers and create a new OAUTH application. Give the application a name and define the
authorized redirect URIs as per the section [Redirect URI](#redirect-uri). Register the application and note the Client ID and Client Secret.

Configure authn.provider to use github to authenticate users:

```yaml
authn:
  provider:
    type: github
    github:
      client_id: "<client_id>"
      client_secret: "<client_secret>"
```

Note: `forward-auth` uses GitHub's `/user` endpoint to retrieve user information. However, this endpoint only returns 
the user's email address if it's visible publicly. If `forward-auth` doesn't find the user's email address, 
it uses the `/user/emails` endpoint and use the user's primary, verified, email address. 
If no primary email address has been set, it uses the first verified address it finds.
