// Loading and rewriting an existing SealedSecret manifest (edit mode).
import { parseAllDocuments, stringify } from './vendor/yaml.js';
import { SCOPES } from './kubeseal.js';

const CLUSTER_WIDE = 'sealedsecrets.bitnami.com/cluster-wide';
const NAMESPACE_WIDE = 'sealedsecrets.bitnami.com/namespace-wide';
const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration';
// Server-populated metadata that must not be applied back.
const RUNTIME_METADATA = ['creationTimestamp', 'resourceVersion', 'uid', 'generation', 'managedFields', 'selfLink'];

function detectScope(...annotationSets) {
  for (const a of annotationSets) {
    if (a?.[CLUSTER_WIDE] === 'true') return SCOPES.clusterWide;
    if (a?.[NAMESPACE_WIDE] === 'true') return SCOPES.namespaceWide;
  }
  return SCOPES.strict;
}

/**
 * Parses YAML (or JSON) text containing a SealedSecret, e.g. a kubeseal output file
 * or `kubectl get sealedsecret -o yaml`. Throws with a user-facing message.
 */
export function parseSealedSecret(text) {
  let docs;
  try {
    docs = parseAllDocuments(text);
  } catch (e) {
    throw new Error(`Nem értelmezhető YAML: ${e.message}`);
  }
  if (!Array.isArray(docs)) docs = [docs];
  const broken = docs.find((d) => d.errors?.length);
  if (broken) throw new Error(`Nem értelmezhető YAML: ${broken.errors[0].message.split('\n')[0]}`);

  const objects = docs.map((d) => d.toJS()).filter(Boolean);
  const items = objects.flatMap((o) => (o.kind === 'List' && Array.isArray(o.items) ? o.items : [o]));
  const sealed = items.filter((o) => o?.kind === 'SealedSecret');
  if (!sealed.length) throw new Error('Nem található SealedSecret (kind: SealedSecret) a beillesztett szövegben.');
  if (sealed.length > 1) throw new Error('Több SealedSecret van a szövegben; egyszerre csak egyet lehet módosítani.');

  const manifest = structuredClone(sealed[0]);
  const metadata = manifest.metadata ?? {};
  const spec = manifest.spec ?? {};
  if (!spec.encryptedData || typeof spec.encryptedData !== 'object') {
    throw new Error('A SealedSecretben nincs spec.encryptedData (a régi spec.data formátum nem támogatott).');
  }
  if (!metadata.name) throw new Error('Hiányzik a metadata.name.');

  delete manifest.status;
  for (const field of RUNTIME_METADATA) delete metadata[field];
  if (metadata.annotations) {
    delete metadata.annotations[LAST_APPLIED];
    if (!Object.keys(metadata.annotations).length) delete metadata.annotations;
  }

  const scope = detectScope(metadata.annotations, spec.template?.metadata?.annotations);
  if (scope !== SCOPES.clusterWide && !metadata.namespace) {
    throw new Error('Hiányzik a metadata.namespace, ezért nem tudni, melyik névtérhez tartozik.');
  }

  return {
    manifest,
    name: metadata.name,
    namespace: metadata.namespace ?? '',
    scope,
    type: spec.template?.type ?? 'Opaque',
    encryptedData: { ...spec.encryptedData },
  };
}

/** Renders the manifest with a new spec.encryptedData; everything else is kept as loaded. */
export function updatedYaml(manifest, encryptedData) {
  const out = structuredClone(manifest);
  out.spec.encryptedData = encryptedData;
  return stringify(out, { lineWidth: 0 });
}
