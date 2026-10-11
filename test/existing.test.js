import { describe, it, expect } from 'vitest';
import { parseSealedSecret, updatedYaml } from '../src/existing.js';

const kubectlOutput = `apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  annotations:
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"bitnami.com/v1alpha1"}
  creationTimestamp: "2026-10-11T10:00:00Z"
  generation: 1
  labels:
    app: web
  name: app-secret
  namespace: prod
  resourceVersion: "1234"
  uid: 0d6f1c1e-1111-2222-3333-444455556666
spec:
  encryptedData:
    API_URL: AgCk9q==
    DB_PASSWORD: AgAx7P==
  template:
    metadata:
      labels:
        app: web
      name: app-secret
      namespace: prod
    type: Opaque
status:
  conditions:
  - status: "True"
    type: Synced
`;

describe('parseSealedSecret', () => {
  it('reads kubectl output and strips runtime fields', () => {
    const s = parseSealedSecret(kubectlOutput);
    expect(s).toMatchObject({ name: 'app-secret', namespace: 'prod', scope: 'strict', type: 'Opaque' });
    expect(s.encryptedData).toEqual({ API_URL: 'AgCk9q==', DB_PASSWORD: 'AgAx7P==' });
    expect(s.manifest.status).toBeUndefined();
    expect(s.manifest.metadata).toEqual({ labels: { app: 'web' }, name: 'app-secret', namespace: 'prod' });
  });

  it('detects scopes from annotations', () => {
    const cw = kubectlOutput.replace(
      'metadata:\n  annotations:\n',
      'metadata:\n  annotations:\n    sealedsecrets.bitnami.com/cluster-wide: "true"\n',
    );
    expect(parseSealedSecret(cw).scope).toBe('cluster-wide');
    const nw = kubectlOutput.replace(
      'metadata:\n  annotations:\n',
      'metadata:\n  annotations:\n    sealedsecrets.bitnami.com/namespace-wide: "true"\n',
    );
    expect(parseSealedSecret(nw).scope).toBe('namespace-wide');
  });

  it('picks the SealedSecret from a multi-document file and accepts JSON', () => {
    const multi = `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n---\n${kubectlOutput}`;
    expect(parseSealedSecret(multi).name).toBe('app-secret');
    const json = JSON.stringify({ kind: 'SealedSecret', metadata: { name: 'a', namespace: 'b' }, spec: { encryptedData: { k: 'v' } } });
    expect(parseSealedSecret(json).encryptedData).toEqual({ k: 'v' });
  });

  it('rejects unusable input with a clear message', () => {
    expect(() => parseSealedSecret('kind: Secret\nmetadata:\n  name: x')).toThrow(/Nem található SealedSecret/);
    expect(() => parseSealedSecret('kind: SealedSecret\nmetadata:\n  name: x\nspec:\n  data: abc')).toThrow(/encryptedData/);
    expect(() => parseSealedSecret('kind: SealedSecret\nmetadata:\n  name: x\nspec:\n  encryptedData: {k: v}')).toThrow(/namespace/);
    expect(() => parseSealedSecret('a: [1, 2')).toThrow(/Nem értelmezhető YAML/);
  });
});

describe('updatedYaml', () => {
  it('replaces only encryptedData and keeps the rest', () => {
    const s = parseSealedSecret(kubectlOutput);
    const yaml = updatedYaml(s.manifest, { API_URL: 'AgCk9q==', DB_PASSWORD: 'NEW==', REDIS: 'R==' });
    expect(yaml).toContain('    API_URL: AgCk9q==\n');
    expect(yaml).toContain('    DB_PASSWORD: NEW==\n');
    expect(yaml).toContain('    REDIS: R==\n');
    expect(yaml).toContain('      labels:\n        app: web');
    expect(yaml).not.toContain('status');
    expect(yaml).not.toContain('resourceVersion');
    expect(s.manifest.spec.encryptedData.DB_PASSWORD).toBe('AgAx7P=='); // input not mutated
  });
});
