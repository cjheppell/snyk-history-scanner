# snyk-history-scanner

A very thin wrapper around the Snyk CLI tool to make it possible to monitor specific versioned releases of software.

## Install

Download the binary for your OS from the releases page.

You'll also need the `snyk` cli installed on the machine too.

## Usage


```bash
snyk-history-scanner --org=<SNYK_ORG> --product=<PRODUCT_NAME> --version=<RELEASE_VERSION> [your-chosen-language]
```

Where chosen language is as follows:

| Language    | Flag        |
| ----------- | ----------- |
| .NET        | `--dotnet`  |
| JavaScript  | `--npm`     |
| Java        | `--java`    |
| Go          | `--golang`  |

You can provide multiple flags in a project that has multiple languages.

This will enumerate all the files on disk and find manifest files relevant to your chosen language. It will then invoke snyk as such:

```bash
snyk monitor --file=<relative_path_to_manifest> --project-name=<relative_path_to_manifest>@<version> --remote-repo-url=<product_name>@<release_version> --org=<snyk_org>
```

### Additional snyk monitor flags

To pass extra Snyk options to the generated `snyk monitor` calls, you can use the following method:

```bash
snyk-history-scanner --org=foo --product=bar --version=0.1 --golang -- --policy-path=.snyk --dev
```

## Credit

This is heavily inspired, and effectively a binary wrapper, for the code available here: https://github.com/paulsnyk/snyk-monitor-all-projects/blob/c95eee6fd0ad637e29158b24d9cc5e45e09eeba0/monitor.js
