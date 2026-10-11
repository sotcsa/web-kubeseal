# web-kubeseal

Böngészőben futó `kubeseal`: gépelés közben azonnal mutatja az eredmény `SealedSecret` YAML-t.

- Kötelező: **namespace**, **name** és a sealed-secrets controller **nyilvános tanúsítványa** (PEM).
- Tetszőleges számú kulcs-érték pár dinamikusan hozzáadható / törölhető (`Opaque` secret).
- **Image pull secret** (`kubernetes.io/dockerconfigjson`) registry, felhasználónév, jelszó és opcionális e-mail alapján.
- Scope: `strict` (alapértelmezett), `namespace-wide`, `cluster-wide`.

Minden a böngészőben történik (WebCrypto), nincs backend: a tanúsítvány és a titkok nem hagyják el a gépet.

A tanúsítvány lekérése a clusterből:

```sh
kubeseal --fetch-cert > cert.pem
```

## Titkosítás

Ugyanaz a formátum, mint a `kubeseal` (`HybridEncrypt`): véletlen 32 bájtos AES-256-GCM kulcs (nulla nonce),
amit RSA-OAEP (SHA-256) titkosít a controller kulcsával, a scope-nak megfelelő címkével
(`namespace/name`, `namespace` vagy üres). Kimenet: `uint16 hossz || RSA titkosított kulcs || AES-GCM titkosított adat`, base64-ben.

A tesztek a `test/fixtures` alatti **csak tesztre szánt** kulcspárral ellenőrzik, hogy az eredmény visszafejthető.
A kimenetet a valódi `kubeseal --recovery-unseal` is sikeresen visszafejti.

## Fejlesztés

```sh
npm install
npm run dev     # fejlesztői szerver
npm test        # tesztek
npm run build   # statikus build a dist/ mappába
```

A `dist/` tartalma bármilyen statikus tárhelyre kitehető. A `main` ágra kerülő változásokat a
`Deploy` workflow GitHub Pages-re publikálja (ehhez a repo beállításaiban a Pages forrását
„GitHub Actions”-re kell állítani).
