# Register OAuth apps

## Step 2: create provider credentials

This guide uses GitHub as the OAuth provider throughout. The callback URL must match both the provider registration and the mediator configuration exactly.

### GitHub

1. In GitHub, open **Settings > Developer settings > OAuth Apps > New OAuth App**. Create a [GitHub OAuth App](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app), not a GitHub App.
2. Set the homepage URL to `https://app.example.com` and the authorization callback URL to:

   ```text
   https://auth.example.com/oauth/github/callback
   ```

3. Select **Register application**, copy the client ID, and choose **Generate a new client secret**. Keep **Expire user access tokens** enabled. GitHub can return refresh tokens for expiring user access tokens, and the mediator stores and uses them when needed. Request only the scopes your frontend's GitHub API calls require; the configuration example starts with `read:user` and `user:email`.

Continue with [configuration](configuration.md).
