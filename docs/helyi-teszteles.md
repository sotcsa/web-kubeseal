# Helyi tesztelés

Ez a leírás két dolgot fed le:

1. [Az alkalmazás futtatása és tesztjei a saját gépeden](#1-az-alkalmazás-futtatása-helyben)
2. [Végponttól végpontig tesztelés minikube-bal](#2-végponttól-végpontig-tesztelés-minikube-bal): a generált SealedSecretből valódi Kubernetes Secret lesz.

## 1. Az alkalmazás futtatása helyben

Node.js 22 kell hozzá.

```sh
npm install
npm run dev        # http://localhost:5173
npm test           # unit tesztek (titkosítási formátum)
npx playwright install chromium   # egyszer, a böngészős tesztekhez
npm run test:e2e   # böngészős tesztek, asztali és mobil nézet
npm run build      # statikus build a dist/ mappába
```

Build nélkül is működik: bármilyen statikus szerver kiszolgálhatja a repó gyökerét, például `python3 -m http.server 8000`,
majd http://localhost:8000/. A WebCrypto miatt `localhost`-on vagy HTTPS-en kell megnyitni.

## 2. Végponttól végpontig tesztelés minikube-bal

A végén egy helyi minikube clusterben fut a Sealed Secrets controller, és a web kubeseal által generált
YAML-ból a controller valódi Secretet készít. Ehhez nem kell kubeseal CLI. Privát registry csak az image pull
secret utolsó lépéséhez kell.

### Előfeltételek

| Eszköz | Mire kell | Telepítés |
| --- | --- | --- |
| Docker (vagy más minikube driver) | ebben fut a cluster | [docs.docker.com](https://docs.docker.com/get-docker/) |
| minikube | helyi Kubernetes cluster | `brew install minikube` vagy [minikube start](https://minikube.sigs.k8s.io/docs/start/) |
| kubectl | a cluster kezelése | `brew install kubectl` vagy `minikube kubectl --` |
| Helm (opcionális) | a controller telepítése chartból | `brew install helm` |
| kubeseal CLI (opcionális) | tanúsítvány lekérése, offline ellenőrzés | `brew install kubeseal` |

### 2.1 Minikube cluster indítása

```sh
minikube start --driver=docker --cpus=2 --memory=4g
kubectl config current-context   # minikube
kubectl get nodes                # STATUS: Ready
```

A SealedSecret a saját névterébe kerül, ezért a névtérnek léteznie kell az apply előtt:

```sh
kubectl create namespace demo
```

### 2.2 Sealed Secrets controller telepítése

A controllert a `kube-system` névtérbe telepítsd `sealed-secrets-controller` néven, mert a kubeseal CLI
alapból ezt keresi. Két egyenértékű út van, elég az egyik.

**A) Helm chart (ajánlott)**

```sh
helm repo add sealed-secrets https://bitnami.github.io/sealed-secrets
helm repo update
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system \
  --set-string fullnameOverride=sealed-secrets-controller
```

**B) Egyetlen manifest kubectl-lel**

A legfrissebb verziót a [releases oldalon](https://github.com/bitnami/sealed-secrets/releases) találod.
A web kubeseal kimenetét a 0.40.0-s controller (Helm chart 2.20.0) sikeresen visszafejti.

```sh
VERSION=0.40.0
kubectl apply -f https://github.com/bitnami/sealed-secrets/releases/download/v${VERSION}/controller.yaml
```

**Ellenőrzés**

```sh
kubectl -n kube-system rollout status deploy/sealed-secrets-controller
kubectl get crd sealedsecrets.bitnami.com
kubectl -n kube-system logs deploy/sealed-secrets-controller | head
```

Indításkor a controller RSA kulcspárt generál, és a `kube-system` névtérben tárolja. Ez a kulcs a clusterhez
tartozik: új cluster új kulcsot jelent, és a régi SealedSecretek ott már nem fejthetők vissza.

### 2.3 Nyilvános tanúsítvány lekérése

A tanúsítvány nem titok, nyugodtan másolható.

kubeseal CLI-vel:

```sh
kubeseal --fetch-cert \
  --controller-name sealed-secrets-controller \
  --controller-namespace kube-system > cert.pem
```

Csak kubectl-lel:

```sh
kubectl -n kube-system get secret \
  -l sealedsecrets.bitnami.com/sealed-secrets-key=active \
  -o jsonpath='{.items[0].data.tls\.crt}' | base64 -d > cert.pem
head -1 cert.pem   # -----BEGIN CERTIFICATE-----
```

### 2.4 SealedSecret generálása és alkalmazása

1. Nyisd meg a web kubesealt: https://sotcsa.github.io/web-kubeseal/ vagy a helyi `npm run dev` példányt.
2. Namespace: `demo`, Name: `app-secret`.
3. Illeszd be vagy húzd be a `cert.pem` tartalmát. A tanúsítvány alatt zöld pipának kell megjelennie.
4. Kulcs-érték párok, például `DB_PASSWORD` = `hunter2` és `API_TOKEN` = `abc123`.
5. Kattints a letöltés ikonra. A fájl neve `app-secret.sealedsecret.yaml` lesz.

```sh
kubectl apply -f app-secret.sealedsecret.yaml

# a SealedSecret állapota és eseményei (siker esetén: Unsealed)
kubectl -n demo get sealedsecret app-secret
kubectl -n demo describe sealedsecret app-secret | tail -5

# a létrejött Secret
kubectl -n demo get secret app-secret
kubectl -n demo get secret app-secret -o jsonpath='{.data.DB_PASSWORD}' | base64 -d; echo   # hunter2
```

Egy podban is kipróbálhatod, hogy az alkalmazás látja-e az értéket:

```sh
kubectl -n demo run secret-test --rm -it --restart=Never --image=busybox \
  --overrides='{"spec":{"containers":[{"name":"secret-test","image":"busybox","command":["sh","-c","echo $DB_PASSWORD"],"envFrom":[{"secretRef":{"name":"app-secret"}}]}]}}'
```

Frissítés: módosítsd az értéket a webes felületen, töltsd le újra, és futtasd újra a `kubectl apply`-t.
A controller felülírja a Secretet.

### 2.5 Image pull secret tesztelése

Ehhez kell egy privát registry és egy olvasási jogú token, például GHCR-hez egy `read:packages` jogú GitHub token.

1. A webes felületen: Namespace `demo`, Name `regcred`, típus **Image pull secret**.
2. Registry: például `ghcr.io`, majd a felhasználónév és a token. Az e-mail opcionális.
3. Töltsd le és alkalmazd:

```sh
kubectl apply -f regcred.sealedsecret.yaml
kubectl -n demo get secret regcred -o jsonpath='{.type}'; echo   # kubernetes.io/dockerconfigjson
kubectl -n demo get secret regcred -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d; echo
```

Pod a privát image-dzsel (`pod-private.yaml`):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-image-test
  namespace: demo
spec:
  imagePullSecrets:
    - name: regcred
  containers:
    - name: app
      image: ghcr.io/<felhasznalo>/<privat-image>:<tag>
      command: ["sleep", "3600"]
```

```sh
kubectl apply -f pod-private.yaml
kubectl -n demo get pod private-image-test -w            # Running = siker
kubectl -n demo describe pod private-image-test | tail -10
```

Siker esetén az eseményekben `Successfully pulled image` szerepel. Ha `ErrImagePull` vagy `ImagePullBackOff`
mellett `unauthorized` hiba jelenik meg, rossz a registry neve, a felhasználónév vagy a token.

Ha a névtér minden podja ezt használja, add hozzá a default service accounthoz:

```sh
kubectl -n demo patch serviceaccount default -p '{"imagePullSecrets":[{"name":"regcred"}]}'
```

### 2.6 A strict scope ellenőrzése és hibakeresés

Az app mindig strict scope-pal titkosít, ezért az adat csak a megadott névtérben és néven fejthető vissza.
Ellenőrzés: írd át a YAML-ban a `metadata.name`-et és a `template.metadata.name`-et (más névtérhez a `namespace`
mezőket), majd alkalmazd újra. Mindkét esetben `no key could decrypt secret` hibát kell kapnod.

Hasznos parancsok:

```sh
kubectl -n kube-system logs deploy/sealed-secrets-controller --tail=50
kubectl -n demo get events --sort-by=.lastTimestamp | tail
```

| Üzenet | Ok | Megoldás |
| --- | --- | --- |
| `no matches for kind "SealedSecret"` | nincs telepítve a controller vagy a CRD | 2.2 |
| `namespaces "demo" not found` | a cél névtér nem létezik | `kubectl create namespace demo` |
| `no key could decrypt secret` | más cluster tanúsítványával titkosítottál, vagy a név/névtér nem egyezik azzal, amire titkosítottál | kérd le újra a tanúsítványt (2.3), és generáld újra a YAML-t |
| `Resource "app-secret" already exists and is not managed by SealedSecret` | már van ilyen nevű, kézzel létrehozott Secret | `kubectl -n demo delete secret app-secret`, majd apply újra |
| a pod `ImagePullBackOff` állapotú | rossz registry, felhasználónév vagy token, vagy hiányzik az `imagePullSecrets` | 2.5 |

Offline ellenőrzés a cluster privát kulcsával (kubeseal CLI kell hozzá). A parancs a titkot visszafejtve
kiírja, ezért csak tesztclusteren használd:

```sh
kubectl -n kube-system get secret -l sealedsecrets.bitnami.com/sealed-secrets-key -o yaml > main.key
kubeseal --recovery-unseal --recovery-private-key main.key -o yaml < app-secret.sealedsecret.yaml
```

### 2.7 Takarítás

```sh
kubectl delete namespace demo
rm -f main.key cert.pem
minikube delete   # a teljes cluster, a controller kulcsával együtt
```

`minikube delete` után az új clusterhez újra le kell kérni a tanúsítványt, és minden SealedSecretet újra kell generálni.
