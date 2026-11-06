# Release checklist

Before publishing a version:

- Run clean dependency installation, typecheck, unit tests, build and workerd tests.
- Verify CI on the intended `main` revision without bypassing branch protections.
- Check dependency advisories, source attribution, links and package metadata.
- Check real hosted source freshness, tools and feeds with bounded requests.
- Keep README claims and labelled recorded examples consistent with the product.
- Review migration compatibility, backup/rollback and deployment configuration.
- Review resource usage and the limits of cost/abuse controls.
- Enable an available private vulnerability-reporting channel and verify the
  [security policy](../SECURITY.md).
- Prepare the [changelog](../CHANGELOG.md) and choose release/visibility timing.

Publishing the repository, transferring ownership, deploying runtime code and
creating a versioned release are distinct maintainer decisions. The package is
marked `private: true`; ordinary use and self-hosting require no npm publication.
Never publish credentials, private inventories or unreviewed source datasets.
