#!/usr/bin/env python3
"""Report what the gateway did with each request, one request at a time.

Reads the gateway's log and the agent runtime's log and joins them on trace_id. Between them
they answer the question a status code only hints at: was this prompt refused before the
backend ran, or did the backend run and have its reply withheld?

    python3 scripts/inspect_logs.py             # the last 15 minutes
    python3 scripts/inspect_logs.py --since 60  # the last hour
    python3 scripts/inspect_logs.py --raw       # every log line behind each verdict

Run the scenarios first. Records take a minute or two to arrive, so an immediate run can look
empty.

The two logs are needed because the gateway records the two target types differently. For the
Lambda MCP target it logs the prompt, the decision and the policy that acted. For the HTTP
runtime target it logs allow decisions only, so a denial or a suppression leaves nothing
behind. The runtime's own log covers that gap: a prompt that reached the agent appears there,
which makes an input denial an absence and an output suppression a record.
"""
import argparse
import datetime as dt
import json
import re

import boto3

from utils import AWS_REGION, outputs

# The gateway logs requestBody as a Java-style map rather than JSON, so the prompt is picked
# out rather than parsed. The runtime logs it as real JSON, and is read directly.
PROMPT = re.compile(r"prompt=(.*?)(?:}|$)", re.DOTALL)

# The denial and the suppression messages both name the policy the same way, so the phrase is
# what to match on. Do not try to describe the name that follows it: the generated id can
# contain an underscore, and a pattern spelling out its character set drops the name silently.
POLICY = re.compile(r"Policy evaluation denied due to ([^\]]+)")


def read(logs, group, start):
    """Every record in the window. None if the group does not exist yet."""
    found = []
    try:
        pages = logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, startTime=int(start.timestamp() * 1000)
        )
        for page in pages:
            found.extend(json.loads(event["message"]) for event in page["events"])
    except logs.exceptions.ResourceNotFoundException:
        return None
    return found


def runtime_prompts(records):
    """The prompt the agent received, keyed by trace_id.

    A trace present here reached the agent. One that is absent did not, which is the only
    evidence there is that an HTTP runtime target was denied on the way in.
    """
    arrived = {}
    for record in records or []:
        payload = record.get("body", {}).get("request_payload") or {}
        arrived[record["trace_id"]] = payload.get("prompt")
    return arrived


def which_target(lines):
    """Agent or Tool, read off the operation the gateway names."""
    text = " ".join(lines)
    if "InvokeHttp" in text:
        return "Agent"
    if "tools/call" in text or "Executing tool" in text:
        return "Tool"
    return None


# The gateway says so itself when it hands a request to a backend, and it names the target it
# handed it to. Reading that line is what keeps the verdict off an absence: "no record in the
# runtime's log" is also what a late delivery, a disabled delivery and an empty window look like.
INVOKED = re.compile(r"Executing (?:Http request|tool)\b")


def classify(lines, has_policy_object):
    """The verdict, and what became of the backend, from the gateway's log alone.

    Ordered most specific first. The awkward case is a suppressed output on the agent hop,
    which the gateway logs as a success: what separates it from a real success is that the
    policy engine recorded no allow decision for a request the gateway did hand on.
    """
    text = " ".join(lines)
    invoked = bool(INVOKED.search(text))

    if "could not be evaluated" in text or "missing an attribute" in text:
        return "NOT EVALUATED", "a policy failed, so every request fails closed"
    if "Output blocked by policy" in text:
        return "SUPPRESSED on output", "ran, and its reply was withheld"
    if "denied" in text.lower():
        return "DENIED on input", "never run"
    if not invoked:
        return "DENIED on input", "never run - the gateway never handed the request on"
    if not has_policy_object:
        return "SUPPRESSED on output", "ran, and no allow decision was recorded for it"
    if "Successfully processed" in text:
        return "allowed", "ran and replied"
    return "no decision recorded", None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--since", type=int, default=15, metavar="MINUTES",
        help="how far back to look, in minutes (default: 15)",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="print the log lines behind each verdict",
    )
    args = parser.parse_args()

    out = outputs()
    missing = [k for k in ("GatewayLogGroupName", "RuntimeLogGroupName") if k not in out]
    if missing:
        raise SystemExit(
            f"error: the stack has no {', '.join(missing)} output.\n"
            "       Redeploy to add the log deliveries:  cd infra && npx cdk deploy"
        )

    start = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=args.since)
    logs = boto3.client("logs", region_name=AWS_REGION)

    gateway = read(logs, out["GatewayLogGroupName"], start)
    if gateway is None:
        raise SystemExit(
            f"error: log group {out['GatewayLogGroupName']} does not exist.\n"
            "       Redeploy, then run the scenarios:  cd infra && npx cdk deploy"
        )
    arrived = runtime_prompts(read(logs, out["RuntimeLogGroupName"], start))

    print(f"last {args.since} minutes, from")
    print(f"  {out['GatewayLogGroupName']}")
    print(f"  {out['RuntimeLogGroupName']}\n")

    # One gateway request is several records. Grouping by request_id puts a request's whole
    # sequence together, and insertion order keeps the oldest request first.
    requests = {}
    for record in gateway:
        requests.setdefault(record["request_id"], []).append(record)

    if not requests:
        print("nothing logged in this window.")
        print("Run the scenarios first, and allow a minute or two for records to arrive.")
        return

    for rows in requests.values():
        lines, policy, prompt, trace = [], None, None, rows[0]["trace_id"]
        has_policy_object = False
        for row in rows:
            body = row.get("body", {})
            has_policy_object = has_policy_object or "policy" in body
            if "requestBody" in body and prompt is None:
                match = PROMPT.search(body["requestBody"])
                prompt = match.group(1).strip() if match else body["requestBody"]
            if "log" in body:
                lines.append(body["log"])
                named = POLICY.search(body["log"])
                policy = named.group(1).strip() if named else policy

        # The gateway does not log the prompt for an HTTP runtime target, so fall back to the
        # runtime's record of what it received.
        if prompt is None:
            prompt = arrived.get(trace)

        target = which_target(lines)
        stamp = dt.datetime.fromtimestamp(rows[0]["event_timestamp"] / 1000, dt.timezone.utc)
        verdict, backend = classify(lines, has_policy_object)

        if prompt:
            shown = f'"{prompt}"'
        elif target == "Agent":
            # Not a limit of this script. Nothing records it: the gateway logs no request body
            # for an HTTP runtime target, and the runtime never saw the prompt.
            shown = "not recorded - the gateway does not log request bodies for HTTP targets"
        else:
            shown = "not recorded"

        print(f"{stamp:%H:%M:%S}  Call to {target or 'an unrecognised target'}")
        print(f"          verdict  {verdict}")
        print(f"          prompt   {shown}")
        if policy:
            print(f"          policy   {policy}")
        if backend:
            print(f"          backend  {backend}")
        if args.raw:
            for line in lines:
                print(f"          .        {line}")
        print()


if __name__ == "__main__":
    main()
