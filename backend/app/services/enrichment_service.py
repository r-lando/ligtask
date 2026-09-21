from copy import deepcopy


REMEDIATION_RULES = {
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
            "A value resembling a credential or "
            "secret was assigned directly within a "
            "repository file."
        ),
        "recommendation": (
            "Remove the secret from tracked source "
            "files, rotate the exposed credential if "
            "it is valid, and load sensitive values "
            "through an appropriate secret-management "
            "or environment mechanism."
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
            "Remove the exposed secret and rotate "
            "it if it is still valid."
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