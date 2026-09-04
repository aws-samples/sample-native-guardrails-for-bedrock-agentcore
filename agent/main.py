"""The agent behind the gateway's runtime target.

Two deliberate choices here, both of which make the demo easier to follow.

It uses nothing outside the standard library. AgentCore Runtime accepts a zip of
code, then scans every native binary in it and checks the ELF headers are arm64.
A wheel built on Windows or on an Intel Mac fails that check, and the runtime
lands in CREATE_FAILED with a message about incompatible binaries. Depending on
nothing means there are no binaries to get wrong, so the same zip builds
anywhere.

It also does not call a model. What this repo has to show is a guardrail policy
at the gateway reading the agent's input and output, and that works the same way
whether the response came from Claude or from a constant. A canned response keeps
the thing under test in view. See README for swapping in a real one.

The HTTP contract is fixed by AgentCore Runtime: bind 0.0.0.0:8080 and serve
POST /invocations and GET /ping.
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html

The request and response shape, though, is ours to choose, and it is the reason
this file matters more than it looks. The gateway can only apply a guardrail to a
field it knows about, and it only knows the fields that openapi.json declares.
So `prompt` going in and `result` coming back are what the policies name as
context.input.prompt and context.output.result. Change a name here and you have
to change it in openapi.json and in the Cedar statements too.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 123-45-6789 has never been issued by the Social Security Administration - it is
# the standard example number and cannot belong to a real person. It is used in
# preference to something like 000-00-0000 because the guardrail scores it far
# more reliably: an all-zero number is detected only intermittently, which makes
# for a demo that appears to leak PII every few runs.
FAKE_SSN = "123-45-6789"

# Labelled fields ("SSN: ...") score more strongly than a bare number in prose.
CUSTOMER_RECORD = (
    "Customer record - name: Jane Doe; "
    f"SSN: {FAKE_SSN}; "
    "email: jane.doe@example.com; account status: active."
)

BENIGN_REPLY = "Hello! I am a small agent with no model behind me."


def answer(prompt):
    """Pick one of two canned replies.

    A substring check stands in for whatever a real agent would do. One agent
    serves both output-phase cases this way: asking for a record produces PII for
    the suppression policy to catch, anything else passes straight through.
    """
    if "record" in prompt.lower():
        return CUSTOMER_RECORD
    return BENIGN_REPLY


class Handler(BaseHTTPRequestHandler):

    def _send(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        # The platform polls this to decide whether the session is alive. It wants
        # "Healthy" or "HealthyBusy". Deliberately no time_of_last_update: a
        # timestamp that moves on every ping reads as a status that never settles,
        # which stops the idle timeout firing and leaves sessions running until
        # MaxLifetime.
        if self.path == "/ping":
            self._send(200, {"status": "Healthy"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/invocations":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"

        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "body was not JSON"})
            return

        prompt = payload.get("prompt", "") if isinstance(payload, dict) else ""
        if not isinstance(prompt, str):
            self._send(400, {"error": "prompt must be a string"})
            return

        # Logging the prompt is what makes the log show which calls reached the
        # agent: denied calls never appear in it, suppressed ones do.
        print(f"/invocations prompt={prompt!r}", flush=True)

        self._send(200, {"result": answer(prompt)})

    def log_message(self, fmt, *args):
        # The default handler writes to stderr in Apache format, which buries the
        # prompt line above in noise. Ping arrives every few seconds.
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # nosec B104 - container-local server behind the gateway, not a public listener
