# Identity Providers

## Google

`forward-auth` uses Google's OpenID Connect to authnenticate users.

Head to https://console.developers.google.com and create a new project. Create new Credentials and select OAuth Client ID
with "web application" as its application type.

Give the credentials a name and define the authorized redirect URIs (e.g., `https://auth.example.com/api/auth/login`).  
Register the application and note the Client ID and Client Secret.

## GitHub

Since GithHub does not support OpenID Connect, `forward-auth` use the GitHub OAuth2 API to authenticate users.

Head to https://github.com/settings/developers and create a new OAUTH application. Give the application a name and define the
authorized redirect URIs (e.g., `https://auth.example.com/api/auth/login`).  Register the application and note the Client ID and Client Secret.
