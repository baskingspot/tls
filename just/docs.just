# The docs site: the docgen API reference and the guide, on the baskingspot
# theme (baskingspot/nix, docs/README.md), deployed as an assets-only Worker.

[private]
api:
    docgen --root src/root.zig --title tls --repo-url https://github.com/baskingspot/tls --rev main --format json --out docs/data

[doc("Build the site into zig-out/site/tls/: docgen JSON rendered by the theme's api.html, and the guide")]
[group("docs")]
doc: api
    baskingspot-docs build tls

[doc("Build and serve the site locally with live reload")]
[group("docs")]
guide: api
    baskingspot-docs serve tls

[doc("Deploy the rendered site to Cloudflare as an assets-only Worker. Needs CLOUDFLARE_API_TOKEN in the environment, plus CLOUDFLARE_ACCOUNT_ID if the token can see more than one account")]
[group("docs")]
doc-deploy: doc
    wrangler deploy
