#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { GuardrailsDemoStack } from '../lib/guardrails-demo-stack';

// Guardrails in AgentCore Policy are available in these Regions only. Deploying
// anywhere else fails with "Guardrails policies are not enabled for this account",
// which reads like a missing entitlement rather than a Region problem, so the check
// happens here where the message can say what is actually wrong.
// https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-guardrails-in-policies.html
const GUARDRAIL_REGIONS = ['us-east-1', 'eu-west-2', 'eu-north-1', 'ap-southeast-2', 'ap-northeast-1'];

const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = process.env.AWS_REGION ?? process.env.CDK_DEFAULT_REGION;

if (!region) {
  throw new Error('No Region. Set AWS_REGION, or a region in your AWS profile.');
}

if (!GUARDRAIL_REGIONS.includes(region)) {
  throw new Error(
    `Region ${region} does not support guardrails in AgentCore Policy.\n` +
      `Supported: ${GUARDRAIL_REGIONS.join(' ')}\n` +
      `Set one and deploy again, for example: AWS_REGION=us-east-1 npx cdk deploy`
  );
}

const app = new App();

new GuardrailsDemoStack(app, 'BedrockGuardrails-AgentcoreGateway-Demo', {
  env: { account, region },
  description: 'Bedrock Guardrails enforced in AgentCore Gateway policy, on both the agent hop and the tool hop',
});
