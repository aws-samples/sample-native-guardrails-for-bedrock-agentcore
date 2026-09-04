"""The Lambda behind the AgentCore Gateway MCP tool `ask_agent`.

This function has no content filtering, moderation, or redaction logic in it.
Enforcement happens in policy at the gateway, which is what the sample sets out to
show, so the tool can be naive and still be safe to call.

Nothing here relates to the two input-phase scenarios: a violent or injection-shaped
prompt is denied before the gateway invokes this function, so there is nothing for
the tool to do about it. The output phase is different, because a policy can only
suppress a response the tool has already produced. That is why this returns a
synthetic customer record with an SSN in it when the prompt asks for a record, and
why its log shows an invocation for a suppressed call but not for a denied one.
"""

# 123-45-6789 has never been issued by the Social Security Administration - it is
# the standard example number and cannot belong to a real person. It is used here
# in preference to something like 000-00-0000 because the guardrail scores it far
# more reliably: an all-zero number is detected only intermittently, which makes
# for a demo that appears to leak PII every few runs.
FAKE_SSN = "123-45-6789"

# Labelled fields ("SSN: ...") score more strongly than a bare number in prose.
CUSTOMER_RECORD = (
    "Customer record - name: Jane Doe; "
    f"SSN: {FAKE_SSN}; "
    "email: jane.doe@example.com; account status: active."
)

BENIGN_REPLY = "Hello! I'm a Lambda function."


def handler(event, context):
    # Demo scaffolding only: a substring check picks which canned reply to send,
    # so that one tool serves both the suppressed and the pass-through case. A
    # real tool would look the record up; nothing here depends on how it decides.
    prompt = (event or {}).get("prompt", "")
    leaks_pii = "record" in prompt.lower()

    # Logging the prompt is what makes the log show which calls reached the function:
    # denied calls never appear in it, suppressed ones do.
    print(f"ask_agent invoked with prompt={prompt!r} returning_pii={leaks_pii}")

    return {
        "statusCode": 200,
        "body": CUSTOMER_RECORD if leaks_pii else BENIGN_REPLY,
        "event": event,
    }
