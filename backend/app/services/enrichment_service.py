from copy import deepcopy


# Exact known rule IDs only; never infer a fix from an arbitrary title/message.
TARGETED_GUIDANCE = {
    "pg-open": {
        "recommendation": "Check the flagged :value placeholder and the SQL quotes around it. Prefer a normal value placeholder and pass the value separately, letting pg-promise handle quoting. Do not use double quotes to surround SQL string values. Test inputs containing quotes and SQL-like text. This scan has not tested a deployed attack.",
        "action": "Replace the open :value placeholder with normal value formatting and separately supplied input.",
    },
    "pg-raw": {
        "recommendation": "Check the flagged pg-promise value and its matching placeholder. Replace :raw or ^ with a normal escaped value placeholder for user data, keeping the value separate from the SQL text. For table or column names, choose from a fixed allowed list and use the library's identifier formatting instead of raw user text. Test inputs containing quotes and unexpected SQL text. This scan has not tested a deployed attack.",
        "action": "Remove raw SQL formatting from the user-controlled value; use normal value formatting.",
    },
    "sql": {
        "recommendation": "Check where the query values come from. Keep the SQL statement separate from user input: use your database library's parameter placeholders and pass values separately, rather than joining them into the query text. For table names, column names, or sort options, choose from a fixed allowed list. Test normal inputs and inputs containing quotes; they should be treated as data, not SQL instructions. This scan has not tested a deployed attack.",
        "action": "Replace joined SQL values with parameter placeholders and separately supplied values.",
    },
    "shell": {
        "recommendation": "Check whether a user can control the command or its arguments. Prefer a library that performs the task without running a shell. If a process is needed, choose a fixed non-shell executable, pass arguments separately with shell mode disabled, and allow only the values and options your app needs. Passing an argument list to sh or bash with -c still runs shell commands. Test that unexpected options and command characters cannot change the intended task. This scan has not tested a deployed attack.",
        "action": "Stop putting user input into shell commands; use a fixed non-shell program with validated arguments.",
    },
    "eval": {
        "recommendation": "Check where the evaluated text comes from. Do not run user input as JavaScript. For numbers, convert the input to a number and reject non-finite or out-of-range values before using it. For JSON, use JSON.parse and validate the resulting structure. For calculations, use a restricted expression parser rather than eval or Function. Test that invalid input is rejected without being executed. This scan has not tested a deployed attack.",
        "action": "Replace dynamic JavaScript execution with parsing and validation for the data you expect.",
    },
}
TARGETED_RULES = {
    "semgrep_rules.v1.javascript.express.security.injection.koa-request-sequelize-query": "sql",
    "semgrep_rules.v1.javascript.express.security.injection.pg-promise-request-open-value": "pg-open",
    "semgrep_rules.v1.javascript.express.security.injection.pg-promise-request-raw-value": "pg-raw",
    "overlapping-sql-warnings": "sql",
    "semgrep_rules.v1.javascript.express.security.injection.tainted-sql-string": "sql",
    "semgrep_rules.v1.javascript.sequelize.security.audit.express-sequelize-injection": "sql",
    "semgrep_rules.v1.javascript.sequelize.security.audit.sequelize-raw-query": "sql",
    "overlapping-eval-warnings": "eval",
    "semgrep_rules.v1.javascript.browser.security.eval-detected": "eval",
    "semgrep_rules.v1.javascript.lang.security.audit.code-string-concat": "eval",
    **{f"semgrep_rules.v1.javascript.express.security.injection.{name}": "shell" for name in (
        "request-to-shell-exec", "request-to-shell-exec-helper", "request-to-explicit-shell-arguments")},
}


REMEDIATION_RULES = {
    "firebase-browser-config": {
        "description": "An API key was found in a Firebase browser configuration object. These keys identify the project and are normally public. This is not a confirmed private-secret leak; access restrictions were not checked.",
        "recommendation": "Verify that the key is limited to the intended Firebase services and that database and storage access rules protect user data. Never put service-account private keys or unrelated private API keys in browser code.",
        "reference_type": "TALGED Rule Guidance",
    },
    "browser-html-write": {
        "description": "JavaScript writes HTML at this location. Multiple rules flagged the same location; this is one review item, not multiple confirmed vulnerabilities. An attack depends on whether someone can control the inserted value and whether it is safely handled.",
        "recommendation": "Trace the inserted value. Use textContent when displaying plain text. If HTML is required, use a maintained HTML sanitizer and handle attribute values safely. Do not remove safe static markup simply to silence the warning.",
        "reference_type": "TALGED Rule Guidance",
    },
    # -------------------------------------------------
    # Correlated configuration findings
    # -------------------------------------------------

    "docker-container-root": {
        "description": (
            "The container may run with elevated "
            "privileges because an explicit non-root "
            "user is not configured."
        ),
        "recommendation": (
            "Configure the container to run as a "
            "dedicated non-root user using the "
            "Dockerfile USER instruction."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    # -------------------------------------------------
    # TALGED configuration findings
    # -------------------------------------------------

    "docker-root-user": {
        "description": (
            "The Dockerfile does not explicitly "
            "configure a non-root user for the "
            "container."
        ),
        "recommendation": (
            "Create or select a dedicated non-root "
            "user and use the Dockerfile USER "
            "instruction before the final runtime "
            "command."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "docker-latest-tag": {
        "description": (
            "The Dockerfile uses the latest image "
            "tag, which does not identify a specific "
            "base-image version."
        ),
        "recommendation": (
            "Pin the base image to an appropriate "
            "specific version or immutable digest "
            "instead of using the latest tag."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "docker-add-instead-of-copy": {
        "description": (
            "The Dockerfile uses ADD even though its "
            "additional behavior may not be required."
        ),
        "recommendation": (
            "Use COPY for ordinary local file "
            "transfers when ADD-specific functionality "
            "is not required."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    # -------------------------------------------------
    # TALGED secret findings
    # -------------------------------------------------

    "generic-secret-assignment": {
        "description": (
            "A value assigned to a password or key-like name matched a detection rule. "
            "The value has not been tested and is not confirmed to be a private credential. "
            "Some browser configuration, such as Firebase client API keys, is intentionally public."
        ),
        "recommendation": (
            "Identify the service and purpose without sharing the value. If it is a private "
            "credential exposed in code, revoke or replace it and move it to protected storage. "
            "For Firebase browser configuration, verify API restrictions and database access "
            "rules; do not assume the key is private or that public configuration is automatically safe."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "aws-access-key-id": {
        "description": (
            "A value matching the structure of an "
            "AWS access key identifier was detected."
        ),
        "recommendation": (
            "Remove the credential from the "
            "repository, revoke or rotate it if "
            "valid, and store credentials outside "
            "tracked source files."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "github-token": {
        "description": (
            "A value matching the structure of a "
            "GitHub authentication token was "
            "detected."
        ),
        "recommendation": (
            "Remove the token from the repository, "
            "revoke or rotate it if valid, and use "
            "an appropriate secret-management "
            "mechanism."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "private-key": {
        "description": (
            "Private-key material was detected in a "
            "repository file."
        ),
        "recommendation": (
            "Remove the private key from the "
            "repository, replace the affected key "
            "pair if necessary, and store private "
            "keys in an appropriate protected "
            "location."
        ),
        "reference_type": "TALGED Rule Guidance",
    },

    "database-connection-string": {
        "description": (
            "A database connection string that may "
            "contain sensitive connection information "
            "was detected."
        ),
        "recommendation": (
            "Remove sensitive database connection "
            "information from tracked files and load "
            "it through protected configuration or "
            "secret-management mechanisms."
        ),
        "reference_type": "TALGED Rule Guidance",
    },
}


def get_default_recommended_action(finding, predefined_rule=None):
    """
    Provide a short, plain-language action the user
    can take, separate from the fuller prose
    recommendation.
    """
    if predefined_rule and predefined_rule.get("action"):
        return (
            predefined_rule["action"]
        )

    category = (
        finding.get(
            "category",
            "",
        )
        or finding.get(
            "rule_id",
            "",
        )
    ).upper()

    if category == "DEPENDENCY":
        return (
            "Update this dependency to a version "
            "without the known flaw."
        )

    if category == "SECRET":
        return (
            "Remove the secret from the code and "
            "rotate it if it may still be active."
        )

    if category == "SAST":
        return (
            "Review the flagged code and apply the "
            "fix described in the guidance."
        )

    if category == "CONFIGURATION":
        return (
            "Adjust the configuration to the safe "
            "values described above."
        )

    return (
        "Review this finding and follow its "
        "remediation guidance."
    )


def get_default_description(finding):
    """
    Create a safe fallback description using
    information already supplied by the scanner.
    """
    message = finding.get("message")

    if message:
        return message

    return (
        "A potential security issue was detected "
        "during repository assessment."
    )


def get_default_recommendation(finding):
    """
    Provide conservative fallback guidance for
    findings without a predefined TALGED rule.
    """
    category = finding.get(
        "category",
        ""
    ).upper()

    if category == "DEPENDENCY":
        package = finding.get("package")

        if package:
            return (
                f"Review the advisory affecting "
                f"{package} and update the dependency "
                f"to a non-affected version when "
                f"appropriate."
            )

        return (
            "Review the vulnerability advisory and "
            "update the affected dependency to a "
            "non-affected version when appropriate."
        )

    if category == "SAST":
        return (
            "Review the affected code and the "
            "scanner-provided guidance, then apply "
            "an appropriate secure implementation."
        )

    if category == "SECRET":
        return (
            "Remove the sensitive value from tracked "
            "repository files and rotate the "
            "credential if it is valid."
        )

    if category == "CONFIGURATION":
        return (
            "Review the affected configuration and "
            "apply the recommended secure "
            "configuration for the identified issue."
        )

    return (
        "Review the finding and apply an appropriate "
        "security remediation based on the affected "
        "component."
    )


def determine_guidance_source(
    finding,
    predefined_rule,
):
    """
    Identify where the remediation guidance came
    from without inventing an external reference.
    """
    if predefined_rule:
        return predefined_rule.get(
            "reference_type",
            "TALGED Rule Guidance",
        )

    scanner = finding.get(
        "scanner",
        "Scanner",
    )

    if scanner == "OSV":
        return "OSV Advisory"

    if scanner == "Semgrep":
        return "Semgrep Finding"

    if scanner == "Multiple":
        return "Correlated Scanner Evidence"

    return "Scanner Finding"


def get_default_recommended_action(finding):
    """
    Provide a short, plain-language action a
    developer can take right away, kept separate
    from the longer recommendation prose.
    """
    category = finding.get(
        "category",
        "",
    ).upper()

    if category == "DEPENDENCY":
        return (
            "Update the affected dependency to a "
            "secure version."
        )

    if category == "SAST":
        return (
            "Review the flagged code and fix the "
            "unsafe pattern."
        )

    if category == "SECRET":
        return (
            "Check whether this is a private credential; replace it if exposed."
        )

    if category == "CONFIGURATION":
        return (
            "Apply the recommended secure "
            "configuration to the affected file."
        )

    return (
        "Review this finding and apply the "
        "suggested fix."
    )


def enrich_finding(finding):
    """
    Add standardized explanatory and remediation
    fields to one normalized/consolidated finding.
    """
    enriched = deepcopy(finding)

    rule_id = finding.get("rule_id")

    predefined_rule = (
        REMEDIATION_RULES.get(
            rule_id
        )
    )

    if not predefined_rule and finding.get("category") == "SAST":
        rule = str(rule_id or "")
        if rule.endswith(("insecure-innerhtml", "insecure-document-method", "html-in-template-string", "react-unsanitized-method")):
            predefined_rule = dict(REMEDIATION_RULES["browser-html-write"])
            predefined_rule["description"] = "A rule flagged HTML construction or insertion at this location. Review the inserted values and where the HTML is used. This alone does not prove that someone can run unwanted scripts in your app."

    if predefined_rule:
        description = (
            predefined_rule[
                "description"
            ]
        )

        recommendation = (
            predefined_rule[
                "recommendation"
            ]
        )
    else:
        description = (
            get_default_description(
                finding
            )
        )

        recommendation = (
            get_default_recommendation(
                finding
            )
        )

    enriched["description"] = (
        description
    )

    enriched["recommendation"] = (
        recommendation
    )

    enriched["recommended_action"] = (
        get_default_recommended_action(
            finding
        )
    )

    enriched["guidance_source"] = (
        determine_guidance_source(
            finding,
            predefined_rule,
        )
    )

    if rule_id == "firebase-browser-config":
        enriched["recommended_action"] = "Review Firebase access rules and key restrictions; public configuration alone is not a private-secret leak."
    canonical_rule = str(rule_id or "").removeprefix("backend.")
    family = TARGETED_RULES.get(canonical_rule)
    if finding.get("category") == "SAST" and family:
        guidance = TARGETED_GUIDANCE[family]
        enriched["recommendation"] = guidance["recommendation"]
        enriched["recommended_action"] = guidance["action"]
        enriched["guidance_source"] = "TALGED Rule Guidance"
        # Keep scanner description/message, locations, severity and evidence intact.
    return enriched


def enrich_findings(findings):
    """
    Enrich a collection of findings without
    modifying the original finding objects.
    """
    enriched_findings = []

    for finding in findings:
        enriched_findings.append(
            enrich_finding(
                finding
            )
        )

    return enriched_findings
