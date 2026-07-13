import { describe, expect, it } from 'vitest';

import {
  ApprovalDispatcher,
  ModeUnavailableError,
  buildApprovalEngineFromConfig,
} from '../engine.js';
import { parseTomlConfig } from '../../config/toml-loader.js';

describe('approval mode construction validation', () => {
  it('rejects a direct static override whose sub-engine is unavailable', () => {
    expect(() => new ApprovalDispatcher({
      defaultMode: 'yolo',
      staticOverrides: { prod: 'smart' },
    })).toThrow(/\[approval\.llm\] is not configured/);
  });

  it('does not advertise smart when its configured env api_key was unavailable', () => {
    const cfg = parseTomlConfig(`
[[sources]]
id = "x"
host = "h"
user = "u"
auth = "kerberos"

[approval]
mode = "yolo"

[approval.llm]
endpoint = "https://api.openai.com/v1/chat/completions"
api_key = "env:MISSING_KEY"
model = "gpt-4o-mini"
`, { env: {} });

    const dispatcher = buildApprovalEngineFromConfig({
      defaultMode: cfg.approval?.mode,
      fail_closed: cfg.approval?.fail_closed,
      llm: cfg.approval?.llm,
    }, { manualOpts: { webuiEnabled: false } });

    expect(dispatcher.availableModes()).toEqual(['yolo']);
    expect(() => dispatcher.setGlobalMode('smart')).toThrow(ModeUnavailableError);
  });

  it('keeps a configured unsupported smart provider inert while yolo is selected', () => {
    const dispatcher = buildApprovalEngineFromConfig({
      defaultMode: 'yolo',
      llm: {
        provider: 'anthropic',
        endpoint: 'https://api.anthropic.com/v1/messages',
        model: 'claude-test',
      },
    }, { manualOpts: { webuiEnabled: false } });

    expect(dispatcher.availableModes()).toEqual(['yolo']);
    expect(() => dispatcher.setGlobalMode('smart')).toThrow(ModeUnavailableError);
  });
});
