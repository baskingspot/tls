# The docs site: the Zig API reference and the guide, on the baskingspot
# theme (baskingspot/nix, docs/README.md), deployed as an assets-only Worker.

[doc("Build the site into zig-out/site/tls/: the API reference and the guide")]
[group("docs")]
doc:
    zig build docs
    baskingspot-docs build tls

[doc("Build and serve the site locally with live reload")]
[group("docs")]
guide:
    zig build docs
    baskingspot-docs serve tls

[doc("Deploy the rendered site to Cloudflare as an assets-only Worker. Needs CLOUDFLARE_API_TOKEN in the environment, plus CLOUDFLARE_ACCOUNT_ID if the token can see more than one account")]
[group("docs")]
doc-deploy: doc
    wrangler deploy
