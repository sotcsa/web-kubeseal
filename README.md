# web-kubeseal

Böngészőben futó `kubeseal`: gépelés közben azonnal mutatja az eredmény `SealedSecret` YAML-t.

- Kötelező: **namespace**, **name** és a sealed-secrets controller **nyilvános tanúsítványa** (PEM).
- A tanúsítvány beilleszthető, fájlból betölthető, vagy **URL-ről letölthető**. Az URL-t a böngésző megjegyzi, és
  `?cert=<url>` paraméterrel előre kitöltött link is megosztható a csapattal. A letöltés közvetlenül a böngészőből
  történik, ezért a szervernek engednie kell (CORS), ahogy pl. a `raw.githubusercontent.com` vagy egy publikus bucket teszi.
- **Cluster választó:** a repó gyökerében lévő [`clusters.yaml`](clusters.yaml) név → tanúsítvány párjaiból
  töltődik, egy kattintással betölti a cluster tanúsítványát. A választás megmarad, és `?cluster=<név>` linkkel
  megosztható. A fájl publikus, ahogy az egész repó.
- Tetszőleges számú kulcs-érték pár dinamikusan hozzáadható / törölhető (`Opaque` secret).
- **Image pull secret** (`kubernetes.io/dockerconfigjson`) registry, felhasználónév, jelszó és opcionális e-mail alapján.
- Scope: mindig `strict`, a titok csak a megadott névtérben és néven fejthető vissza. Más scope-ú SealedSecret
  nem módosítható.
- **Meglévő SealedSecret módosítása:** a beillesztett YAML-ban egyes kulcsok értéke cserélhető, kulcs törölhető
  vagy hozzáadható; a többi titkosított érték változatlanul megmarad (mint a `kubeseal --merge-into`).

Minden a böngészőben történik (WebCrypto), nincs backend: a tanúsítvány és a titkok nem hagyják el a gépet.

A tanúsítvány lekérése a clusterből:

```sh
kubeseal --fetch-cert > cert.pem
```

## Tanúsítvány a controllertől, böngészőből

A controller `/v1/cert.pem` végpontja alapból nem küld CORS fejlécet, ezért a böngésző nem engedi az oldalnak
kiolvasni. Ha a controller ingressen keresztül érhető el (ingress-nginx), ezekkel az annotációkkal engedélyezhető
csak erre az oldalra és csak olvasásra:

```yaml
nginx.ingress.kubernetes.io/enable-cors: "true"
nginx.ingress.kubernetes.io/cors-allow-origin: "https://sotcsa.github.io"
nginx.ingress.kubernetes.io/cors-allow-methods: "GET"
```

A tanúsítvány nyilvános adat, ezt engedni nem kockázat. Belső hálózati címnél a Chrome egyszeri engedélyt kérhet
(„helyi hálózat elérése”).

## Titkosítás

Ugyanaz a formátum, mint a `kubeseal` (`HybridEncrypt`): véletlen 32 bájtos AES-256-GCM kulcs (nulla nonce),
amit RSA-OAEP (SHA-256) titkosít a controller kulcsával, `namespace/name` címkével
(strict scope). Kimenet: `uint16 hossz || RSA titkosított kulcs || AES-GCM titkosított adat`, base64-ben.

A tesztek a `test/fixtures` alatti **csak tesztre szánt** kulcspárral ellenőrzik, hogy az eredmény visszafejthető.
A kimenetet a valódi `kubeseal --recovery-unseal` is sikeresen visszafejti.

## Fejlesztés

Részletes helyi tesztelési útmutató, minikube-bal együtt: [docs/helyi-teszteles.md](docs/helyi-teszteles.md).

```sh
npm install
npm run dev     # fejlesztői szerver
npm test        # unit tesztek (titkosítási formátum)
npm run test:e2e  # böngészős tesztek (Playwright, asztali + mobil nézet)
npm run build   # statikus build a dist/ mappába
npm run vendor:yaml  # a src/vendor/yaml.js újragenerálása a yaml csomagból
```

A `dist/` tartalma bármilyen statikus tárhelyre kitehető. Nincs futásidejű függőség, ezért a
nyers forrás (`index.html` + `src/`) is működik böngészőben, akár alútvonalon is.

GitHub Pages: a `main` ágra kerülő változásokat a `CI` workflow `deploy` jobja publikálja, de csak
akkor, ha a tesztek zöldek. Ehhez a repo beállításaiban a Pages forrása „GitHub Actions” legyen.
