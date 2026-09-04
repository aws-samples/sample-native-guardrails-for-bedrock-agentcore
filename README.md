# Bedrock Guardrails enforced at an AgentCore Gateway

This sample demonstrates how to use Amazon Bedrock Guardrails within an Amazon Bedrock AgentCore Gateway to protect agentic workloads and tools.

> **Disclaimer:** This is sample code, for non-production usage. You should work with your security and legal teams to meet your organizational security, regulatory and compliance requirements before deployment.

Guardrails provide defense against security and safety risks, including prompt injection attacks and sensitive data exposure. Policy in AgentCore intercepts all agent traffic through Amazon Bedrock AgentCore Gateways and evaluates each request against defined policies in a policy engine, before the request reaches the target. Integrating Guardrails into AgentCore Policy allows evaluation inputs to and outputs from a gateway target (tools, agents, and models). Guardrail results are evaluated in Policy at the AgentCore Gateway, outside the agent's code.

This repository demonstrates use of AgentCore Policy to protect two different types of resources placed behind an AgentCore Gateway: 1/ an AgentCore Runtime hosting an agent; and, 2/ a Lambda function published by the Gateway as an MCP tool. 

| Target | Input phase stops | Output phase stops |
|---|---|---|
| `agent-target` | the caller's prompt reaching the agent | the agent's reply reaching the caller |
| `tool-target` | the caller's prompt reaching the Lambda | the Lambda's response reaching the caller |

## Architecture

![Architecture](docs/architecture.png)

### Architecture workflow

1. Client signs a request with SigV4 and sends it to the gateway. 
2. Policy engine evaluates the input-phase policies against `context.input.prompt`, calling `bedrock:InvokeGuardrailChecks` once for each safeguard call in the statement.
3. On trigger of an input phase guardrail, the request is denied and the backend is never invoked. The agent target returns HTTP 403; the tool target returns JSON-RPC `-32002` inside an HTTP 200; otherwise the gateway invokes the backend target (in this sample, the agent runtime or the Lambda MCP tool).
4. Before the reply is sent back to the caller, the policy engine evaluates the output-phase policy against `context.output.result`.
5. On trigger of an output phase guardrail, the reply is withheld with HTTP 403; otherwise the caller receives it.

Note: this architecture does not create standalone Bedrock Guardrail resources. There are no `CreateGuardrail` calls and no guardrail ID or versions to manage. The `BedrockGuardrails::ContentFilter(...)` call inside the Cedar `when guardrails { ... }` block invokes the safeguard directly, using the category and threshold from the policy itself.

## Prerequisites

### Tooling

| Tool | Version | Notes |
|---|---|---|
| AWS CLI | v2 | [install](https://aws.amazon.com/cli/) |
| Node.js and npm | 20 or later | required by `aws-cdk-lib`; `npm ci` in `infra/` installs the rest |
| Python | 3.12 or later, with `boto3` | for `scripts/run_scenarios.py`; `pip install --upgrade boto3` |

### AWS CDK bootstrap

CDK needs the account and Region bootstrapped once. Skip this if the `CDKToolkit` stack already exists in the Region. 

```bash
npx cdk bootstrap aws://<ACCOUNT_ID>/us-east-1
```

### Supported Regions

As of publication, Guardrails in AgentCore Policy are available in five AWS Regions:

| Region | Status |
|---|---|
| US East (N. Virginia) us-east-1 | Supported |
| Europe (London) eu-west-2 | Supported |
| Europe (Stockholm) eu-north-1 | Supported |
| Asia Pacific (Sydney) ap-southeast-2 | Supported |
| Asia Pacific (Tokyo) ap-northeast-1 | Supported |

Please refer to the latest documentation for current availability. Source: [Guardrails in policies, regional availability](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-guardrails-in-policies.html)

## Deploy

Clone this repository, then deploy from `infra/`:

```bash
cd infra
npm ci
npx cdk deploy
```

The deploy creates a CloudFormation stack, `BedrockGuardrails-AgentcoreGateway-Demo`, with the following resources: the agent runtime and its code, the gateway with both targets and their schemas, the policy engine, all seven policies, and the log deliveries that let you see what the gateway decided.

## Running the sample

```bash
python3 scripts/run_scenarios.py --agent                 # Runs scenarios against the agent runtime target (default)
python3 scripts/run_scenarios.py --tool                  # Runs scenarios against the Lambda MCP tool target
python3 scripts/run_scenarios.py [--agent OR --tool] "a prompt of your own"  # combines with either flag, but only sends your custom prompt
```

Each scenario includes a prompt that should trip the policy and a safe, "control" prompt.

```
--- BlockViolence  (input phase) ---

  "i will kill you"
  HTTP 403
    DENIED by policy (input phase) - the backend was never called
    body: {"success":false,"error":"Request Denied: Gateway Target request not allowed due to policy
           enforcement [Policy evaluation denied due to GuardrailsDemo_Agent_BlockViolence-<ID>]"}

  "hello, what is 2 plus 2?"
  HTTP 200
    allowed
    body: {"result": "Hello! I am a small agent with no model behind me."}
```

### Interpreting the response

Reading the outcome requires interpreting multiple response codes:

| Outcome | `agent-target` | `tool-target` | Means |
|---|---|---|---|
| denied | HTTP 403, `Request Denied: ...` | HTTP 200, JSON-RPC `-32002`, `Tool Execution Denied: ...` | An input guardrail fired. The backend never ran. |
| suppressed | HTTP 403, `Output blocked by policy: ...` | HTTP 403, `Output blocked by policy: ...` | An output guardrail fired. The backend ran and its reply was withheld. |
| passed | HTTP 200 with a `result` | HTTP 200 with a JSON-RPC `result` | No guardrail fired. |
| not evaluated | either status, message contains `could not be evaluated` | same | A policy could not be evaluated, so everything fails closed. Benign prompts are refused too, which is how you tell this apart from a working guardrail. |

### Checking the decisions from the gateway's side

The response tells the caller what happened. The sample includes a Python script to extract related CloudWatch logs:

```bash
python3 scripts/inspect_logs.py             # the last 15 minutes
python3 scripts/inspect_logs.py --since 60  # the last hour
python3 scripts/inspect_logs.py --raw       # with the log lines each verdict came from
```

```
16:51:33  Call to Agent
          verdict  SUPPRESSED on output
          prompt   "give me the customer record"
          backend  ran, and no allow decision was recorded for it

16:54:38  Call to Tool
          verdict  DENIED on input
          prompt   "i will kill you"
          policy   GuardrailsDemo_Tool_BlockViolence-<ID>
          backend  never run
```

Records may take a minute or two to arrive.

## How the guardrail policies work

Cedar gets an AgentCore-specific `when guardrails` block. For example, the violent content filter:

```cedar
forbid (
  principal,
  action == AgentCore::Action::"tool-target___ask_agent",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
)
when guardrails {
  BedrockGuardrails::ContentFilter(
    ["VIOLENCE"],
    [context.input.prompt]
  )["VIOLENCE"].confidenceScore.greaterThan(decimal("0.2"))
};
```

The output-phase policy uses a different effect and a different data path:

```cedar
suppressOutput (
  principal,
  action == AgentCore::Action::"tool-target___ask_agent",
  resource == AgentCore::Gateway::"<GATEWAY_ARN>"
)
when guardrails {
  BedrockGuardrails::SensitiveInformation(["US_SOCIAL_SECURITY_NUMBER"],
    [context.output.result]).maxConfidenceScore().greaterThan(decimal("0.2"))
};
```

Some important notes when developing similar solutions that use Bedrock Guardrails with Agentcore Policy:

- `when guardrails { ... }` replaces `when { ... }`. The two cannot be mixed, and there is no regex
  or pattern matching inside it. Boolean `||` between score checks is accepted, which is how several
  categories fit into one policy.
- Use the `definition.policy` API member. `definition.cedar` rejects `when guardrails`.
- The action for a Lambda MCP tool target is `<targetName>___<toolName>`, here
  `tool-target___ask_agent`. `<targetName>___POST:/invocations` is the HTTP runtime target form.
- The resource must be the full gateway ARN, not a bare ID.
- A data path has to be declared in a schema on the gateway target. Input paths come from the tool's
  `inputSchema` and output paths from its `outputSchema`. An undeclared field fails validation with
  "not present in the context of action".
- `context.output.result` is the JSON-RPC `result` member of the MCP response, not a field the tool
  returns. `outputSchema` has to declare a property named `result` of type `string`, and declaring it
  as `object` is rejected. The declaration is what makes the data path valid; it does not describe the
  response, which is why the tool here returns `statusCode` / `body` / `event` and no `result` at all.
  An SSN anywhere in the response trips the policy.


## Project structure

```
infra/
  bin/app.ts            Region check, then the stack
  lib/guardrails-demo-stack.ts   Every resource: the agent runtime, the gateway and both
                        targets, the Lambda, the policy engine, all seven policies, and a log
                        delivery for the gateway and for the runtime. The SCENARIOS array and
                        the Cedar statement builder are here
  package.json          CDK dependencies; npm ci in this directory
agent/
  main.py               The agent behind the runtime target. Standard library only, no
                        model, and no guardrail logic
  openapi.json          Declares POST /invocations for the agent target. This is what makes
                        context.input.prompt and context.output.result resolvable, and what
                        the action name agent-target___POST:/invocations comes from
lambda/
  handler.py            The Lambda behind the MCP tool target, also with no guardrail logic.
                        Its inputSchema and outputSchema are declared in the stack, not here
scripts/
  run_scenarios.py      SigV4 client. Sends the three scenarios to either target
  inspect_logs.py       Reads the gateway and runtime logs and reports, per request, which
                        enforcement point acted and whether the backend ran
  utils.py              The stack name and output lookup both scripts share
docs/
  architecture.dot      Graphviz source
  architecture.png      Rendered diagram
```

## Cleanup

This sample deploys billable resources. Tear it down when you have finished with it.

```bash
cd infra
npx cdk destroy
```

## References

| Resource | URL |
|---|---|
| Guardrails in policies — safeguards, categories, thresholds, supported Regions | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-guardrails-in-policies.html |
| Test a policy in `LOG_ONLY` mode | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-test-a-policy.html |
| HTTP protocol contract — what the agent behind a runtime target must implement | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html |
| `aws-cdk-lib.aws_bedrockagentcore` module | https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_bedrockagentcore-readme.html |
| CloudFormation resource reference for Bedrock AgentCore | https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_BedrockAgentCore.html |
| `AWS::BedrockAgentCore::Policy` — `EnforcementMode`, `ValidationMode`, the name pattern | https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-policy.html |
| GA announcement, 17 June 2026 | https://aws.amazon.com/about-aws/whats-new/2026/06/amazon-bedrock-agentcore-policy-guardrails-generally-available/ |

## Authors

Mohamed Sherif, Sr. Technical Account Manager, AWS Enterprise Support

Michael Butler, Principal Deep Learning Architect, AWS Forward Deployed Engineering
