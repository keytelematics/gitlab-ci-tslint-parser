# Converts tslint output into GitLab SAST report format.

Adapted from https://github.com/mgibeau/gitlab-npm-audit-parser

```
Usage: gitlab-ci-tslint-parser [options]

Options:

  -V, --version     output the version number
  -o, --out <path>  output filename, defaults to gl-sast-report.json
  -h, --help        output usage information
```

## How to use

Install this package. Make sure you've installed `tslint`, `tslint-config-security` and configured them together (see https://github.com/webschik/tslint-config-security).

```
npm install --save-dev gitlab-ci-tslint-parser
```

Add the following job to _.gitlab-ci.yml_

```yaml
dependency scanning:
  image: node:10-alpine
  script:
    - npm ci # or yarn install
    - npx tslint --project ./ --format json | npx gitlab-ci-tslint-parser -o gl-sast-report.json
  artifacts:
    reports:
      dependency_scanning: gl-sast-report.json
```

## Test

`cat test/test.json | ./parse.js -o gl-sast-report.json`
