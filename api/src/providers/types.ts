export interface ProviderContext {
  url: string;
  domain: string;
}

export interface ProviderResult {
  triggered: boolean;
  source: string;
  explanation: string;
}

export interface ThreatProvider {
  name: string;
  isConfigured(): boolean;
  check(ctx: ProviderContext): Promise<ProviderResult>;
}