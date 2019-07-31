
// taken from https://gitlab.com/gitlab-org/security-products/analyzers/tslint/blob/master/convert/convert.go
var descriptions = {
	"tsr-detect-unsafe-regexp":                     "Locates potentially unsafe regular expressions, which may take a very long time to run, blocking the event loop.",
	"tsr-detect-non-literal-buffer":                "Detects variable in `new Buffer` argument.",
	"tsr-detect-buffer-noassert":                   "Detects calls to `Buffer` with `noAssert` flag set.",
	"tsr-detect-child-process":                     "Detects instances of `child_process` & non-literal `exec()`",
	"tsr-disable-mustache-escape":                  "Detects `object.escapeMarkup = false`, which can be used with some template engines to disable escaping of HTML entities. This can lead to Cross-Site Scripting (XSS) vulnerabilities.",
	"tsr-detect-eval-with-expression":              "Detects `eval(variable)` which can allow an attacker to run arbitary code inside your process.",
	"tsr-detect-no-csrf-before-method-override":    "Detects Express csrf middleware setup before method-override middleware. This can allow GET requests (which are not checked by csrf) to turn into POST requests later.",
	"tsr-detect-non-literal-fs-filename":           "Detects variable in filename argument of fs calls, which might allow an attacker to access anything on your system.",
	"tsr-detect-non-literal-regexp":                "Detects `RegExp(variable)`, which might allow an attacker to DOS your server with a long-running regular expression.",
	"tsr-detect-non-literal-require":               "Detects `require(variable)`, which might allow an attacker to load and run arbitrary code, or access arbitrary files on disk.",
	"tsr-detect-possible-timing-attacks":           "Detects insecure comparisons (==, !=, !== and ===), which check input sequentially.",
	"tsr-detect-pseudo-random-bytes":               "Detects if pseudoRandomBytes() is in use, which might not give you the randomness you need and expect.",
	"tsr-detect-html-injection":                    "Detects HTML injections.",
	"tsr-detect-sql-literal-injection":             "Detects possible SQL injections in string literals.",
	"tsr-detect-unsafe-cross-origin-communication": "Detects when all windows & frames on your page (including ones that were injected by 3rd-party scripts) may receive your data.",
	"tsr-detect-unsafe-properties-access":          "Detects a potential unsafe access to the object properties",
}

var convert = function (json) {
  parsedData = JSON.parse(json);
  report = {};
  report.version = "2.1";
  report.vulnerabilities = [];
  report.remediations = [];

  var parsePath = function (path) {
    return path.replace(process.cwd() + '/', '');
  }

  parsedData.forEach(advisory => {

    if (advisory.ruleName.substr(0, 4) === "tsr-") {

      report.vulnerabilities.push({
        "category": "sast",
        "name": advisory.failure,
        "message": advisory.failure,
        "cve": parsePath(advisory.name) + ':' + advisory.startPosition.line + ":" + advisory.ruleName,
        "description": descriptions[advisory.ruleName] || advisory.failure,
        "severity": "Low",
        "confidence": "High",
        "scanner": {
          "id": "tslint",
          "name": "TSLint"
        },
        "location": {
          "file": parsePath(advisory.name),
          "start_line": advisory.startPosition.line,
          "end_line": advisory.endPosition.line,
          "dependency": {
            "package": {}
          }
        },
        "identifiers": [
          {
            "type": "tslint_rule_id",
            "name": "TSLint rule ID " + advisory.ruleName,
            "value": advisory.ruleName,
            "url": "https://github.com/webschik/tslint-config-security#" + advisory.ruleName,
          }
        ]
      });
    }
  });

  return JSON.stringify(report, null, '  ');
}

module.exports = convert;
